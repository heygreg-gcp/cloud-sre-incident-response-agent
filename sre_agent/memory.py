"""Context & Memory Management: History Compaction, Persistent Session State, Vertex AI Search, and Async Memory Consolidation.

Implements the capabilities of Category 2 (Context & Memory):
1. History Compaction (`HistoryCompactor`) — token-budget sliding window truncation,
   abstractive summarization, and Vertex AI Context Caching configuration.
2. Persistent Session State (`PersistentSessionStore`, `VertexSearchKnowledgeStore`) —
   parameterized SQLite persistence and Vertex AI Search (`google.cloud.discoveryengine_v1`)
   runbook retrieval with local cosine-similarity vector fallback.
3. Async Memory Operations (`AsyncMemoryConsolidator`) — background `asyncio.create_task`
   and `asyncio.Queue` memory consolidation pipeline to prevent blocking agent turns.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import math
import re
import sqlite3
import uuid
from collections import Counter
from typing import Any, Callable

from sre_agent.observability import DEFAULT_REDACTOR, PIIRedactor

BUILTIN_SRE_RUNBOOKS: list[dict[str, Any]] = [
    {
        "runbook_id": "RB-101-CANARY-ROLLBACK",
        "title": "Canary Release 5xx Error Spike & Latency Regression Rollback",
        "keywords": "checkout-service payment-gateway canary deployment release 5xx 500 503 latency spike rollback NullPointerException",
        "root_cause_pattern": (
            "Faulty canary deployment introducing unhandled exceptions or latency regressions "
            "immediately following a release rollout."
        ),
        "recommended_mitigation_steps": [
            "1. Verify golden signals via query_service_health_metrics to confirm SLO breach.",
            "2. Correlate onset timestamp with recent rollouts via correlate_deployment_change_events.",
            "3. Open a SEV1/SEV2 incident ticket via create_critical_incident_ticket.",
            "4. Request Human-in-the-Loop approval token and execute execute_production_rollback to prior stable version.",
        ],
        "requires_human_approval_for_rollback": True,
    },
    {
        "runbook_id": "RB-204-REDIS-POOL-EXHAUSTION",
        "title": "Auth & Session Service Redis Connection Pool Exhaustion Mitigation",
        "keywords": "auth-service redis connection pool exhaustion timeout saturation high latency PoolExhaustedException",
        "root_cause_pattern": (
            "Connection leak or sudden concurrency surge exhausting upstream Redis pool limits."
        ),
        "recommended_mitigation_steps": [
            "1. Inspect connection timeout clusters via analyze_error_log_anomalies.",
            "2. Check if recent auth-service deployment modified pool timeout settings.",
            "3. Roll back leaked release version with human approval or drain stale worker pods.",
        ],
        "requires_human_approval_for_rollback": True,
    },
    {
        "runbook_id": "RB-309-DOWNSTREAM-GATEWAY-TIMEOUT",
        "title": "Payment Gateway Upstream Timeout & Circuit Breaker Tripping",
        "keywords": "payment-gateway upstream timeout 504 circuit breaker retry storm latency",
        "root_cause_pattern": (
            "Retry storm or downstream settlement provider degradation causing cascading timeouts."
        ),
        "recommended_mitigation_steps": [
            "1. Measure p95/p99 latency and saturation via query_service_health_metrics.",
            "2. Enable adaptive circuit-breaking and shed non-critical retry traffic.",
            "3. If triggered by recent gateway config rollout, execute approved rollback.",
        ],
        "requires_human_approval_for_rollback": True,
    },
]


class HistoryCompactor:
    """Manages conversational context bloat via token-budget sliding windows, summarization, and Vertex AI Context Caching."""

    def __init__(
        self,
        max_token_budget: int = 2048,
        recent_turns_to_keep: int = 4,
        summarizer_fn: Callable[[list[dict[str, str]]], str] | None = None,
    ) -> None:
        if max_token_budget < 10:
            raise ValueError("max_token_budget must be at least 10 tokens.")
        if recent_turns_to_keep < 1:
            raise ValueError("recent_turns_to_keep must be at least 1.")
        self.max_token_budget = max_token_budget
        self.recent_turns_to_keep = recent_turns_to_keep
        self.summarizer_fn = summarizer_fn

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Estimate token count using a deterministic word-piece heuristic (~1.3 tokens/word)."""
        words = text.split()
        return max(1, int(math.ceil(len(words) * 1.3)))

    def total_history_tokens(self, turns: list[dict[str, str]]) -> int:
        """Compute total estimated tokens across a sequence of conversation turns."""
        return sum(self.estimate_tokens(t.get("content", "")) for t in turns)

    def _default_summarize(self, evicted_turns: list[dict[str, str]]) -> str:
        """Produce a structured, high-density summary of evicted historical turns."""
        key_facts: list[str] = []
        for turn in evicted_turns:
            role = turn.get("role", "user")
            content = turn.get("content", "").strip()
            if content:
                snippet = content[:160] + ("..." if len(content) > 160 else "")
                key_facts.append(f"{role}: {snippet}")
        joined = " | ".join(key_facts)
        return f"[COMPACTED_HISTORY_SUMMARY] Prior {len(evicted_turns)} turns consolidated: {joined}"

    def compact_history(self, turns: list[dict[str, str]]) -> list[dict[str, str]]:
        """Compact conversation history when token count or turn count exceeds budget."""
        if (
            len(turns) <= self.recent_turns_to_keep
            and self.total_history_tokens(turns) <= self.max_token_budget
        ):
            return list(turns)

        evicted = turns[: -self.recent_turns_to_keep]
        retained = turns[-self.recent_turns_to_keep :]

        if not evicted:
            return list(retained)

        summary_text = (
            self.summarizer_fn(evicted)
            if self.summarizer_fn is not None
            else self._default_summarize(evicted)
        )
        summary_turn = {"role": "system", "content": summary_text}
        return [summary_turn, *retained]

    @staticmethod
    def build_vertex_context_cache_config(
        system_instruction: str,
        model: str = "gemini-2.5-pro",
        ttl_seconds: int = 3600,
    ) -> dict[str, Any]:
        """Build a Vertex AI Context Caching specification for static SRE constitutions and runbooks."""
        return {
            "model": model,
            "display_name": "sre-incident-constitution-and-runbooks-cache",
            "system_instruction": system_instruction,
            "ttl": f"{int(ttl_seconds)}s",
        }


class PersistentSessionStore:
    """SQLite-backed persistent store for multi-turn conversation state and consolidated incident memories."""

    def __init__(
        self,
        db_path: str = ":memory:",
        redactor: PIIRedactor | None = None,
    ) -> None:
        self.db_path = db_path
        self.redactor = redactor or DEFAULT_REDACTOR
        # Keep a persistent connection for in-memory databases; file DBs open connections per operation
        self._shared_conn: sqlite3.Connection | None = (
            sqlite3.connect(":memory:", check_same_thread=False)
            if db_path == ":memory:"
            else None
        )
        self._initialize_schema()

    def _connect(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return self._shared_conn
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _initialize_schema(self) -> None:
        conn = self._connect()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS session_turns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS consolidated_memories (
                    memory_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    consolidated_lesson TEXT NOT NULL,
                    resolution_steps_json TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                )
                """
            )
            conn.commit()
        finally:
            if self._shared_conn is None:
                conn.close()

    def append_turn(
        self,
        session_id: str,
        role: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Persist a PII-scrubbed conversation turn using parameterized SQL queries."""
        sanitized_content = self.redactor.redact_text(content)
        sanitized_meta = self.redactor.redact_value(metadata or {})
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        conn = self._connect()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO session_turns (session_id, role, content, metadata_json, created_at_utc)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    role,
                    sanitized_content,
                    json.dumps(sanitized_meta),
                    now_utc,
                ),
            )
            conn.commit()
        finally:
            if self._shared_conn is None:
                conn.close()

    def get_session_turns(self, session_id: str) -> list[dict[str, Any]]:
        """Retrieve ordered conversation history for a session ID."""
        conn = self._connect()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT role, content, metadata_json, created_at_utc
                FROM session_turns
                WHERE session_id = ?
                ORDER BY id ASC
                """,
                (session_id,),
            )
            rows = cursor.fetchall()
            return [
                {
                    "role": row[0],
                    "content": row[1],
                    "metadata": json.loads(row[2]),
                    "created_at_utc": row[3],
                }
                for row in rows
            ]
        finally:
            if self._shared_conn is None:
                conn.close()

    def store_consolidated_memory(
        self,
        session_id: str,
        service_name: str,
        consolidated_lesson: str,
        resolution_steps: list[str],
    ) -> str:
        """Persist a long-term incident remediation lesson with PII scrubbing."""
        memory_id = f"mem-{uuid.uuid4().hex[:12]}"
        sanitized_lesson = self.redactor.redact_text(consolidated_lesson)
        sanitized_steps = [self.redactor.redact_text(step) for step in resolution_steps]
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        conn = self._connect()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO consolidated_memories (
                    memory_id, session_id, service_name, consolidated_lesson,
                    resolution_steps_json, created_at_utc
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    memory_id,
                    session_id,
                    service_name,
                    sanitized_lesson,
                    json.dumps(sanitized_steps),
                    now_utc,
                ),
            )
            conn.commit()
            return memory_id
        finally:
            if self._shared_conn is None:
                conn.close()

    def search_consolidated_memories(self, service_name: str) -> list[dict[str, Any]]:
        """Retrieve consolidated post-mortem memories for a given service name."""
        conn = self._connect()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT memory_id, session_id, service_name, consolidated_lesson,
                       resolution_steps_json, created_at_utc
                FROM consolidated_memories
                WHERE service_name = ?
                ORDER BY created_at_utc DESC
                """,
                (service_name,),
            )
            rows = cursor.fetchall()
            return [
                {
                    "memory_id": row[0],
                    "session_id": row[1],
                    "service_name": row[2],
                    "consolidated_lesson": row[3],
                    "resolution_steps": json.loads(row[4]),
                    "created_at_utc": row[5],
                }
                for row in rows
            ]
        finally:
            if self._shared_conn is None:
                conn.close()


class VertexSearchKnowledgeStore:
    """Retrieves SRE runbooks from Google Cloud Vertex AI Search with deterministic vector fallback."""

    def __init__(
        self,
        project_id: str | None = None,
        location: str = "global",
        data_store_id: str | None = None,
        search_client: Any | None = None,
    ) -> None:
        self.project_id = project_id
        self.location = location
        self.data_store_id = data_store_id
        self._search_client = search_client
        self._runbooks = list(BUILTIN_SRE_RUNBOOKS)

    @staticmethod
    def _tokenize(text: str) -> Counter[str]:
        tokens = re.findall(r"[a-z0-9]+", text.lower())
        return Counter(tokens)

    @classmethod
    def _cosine_similarity(cls, query_text: str, doc_text: str) -> float:
        vec_a = cls._tokenize(query_text)
        vec_b = cls._tokenize(doc_text)
        if not vec_a or not vec_b:
            return 0.0
        intersection = set(vec_a.keys()) & set(vec_b.keys())
        numerator = sum(vec_a[t] * vec_b[t] for t in intersection)
        sum_a = sum(v * v for v in vec_a.values())
        sum_b = sum(v * v for v in vec_b.values())
        denominator = math.sqrt(sum_a) * math.sqrt(sum_b)
        if denominator == 0.0:
            return 0.0
        return round(min(1.0, numerator / denominator), 4)

    def search_runbooks(
        self,
        query: str,
        top_k: int = 3,
    ) -> list[dict[str, Any]]:
        """Query Vertex AI Search Discovery Engine or fallback local vector store for SRE runbooks."""
        if self.project_id and self.data_store_id:
            try:
                from google.cloud import discoveryengine_v1

                client = self._search_client or discoveryengine_v1.SearchServiceClient()
                serving_config = (
                    f"projects/{self.project_id}/locations/{self.location}/"
                    f"collections/default_collection/dataStores/{self.data_store_id}/"
                    "servingConfigs/default_search"
                )
                request = discoveryengine_v1.SearchRequest(
                    serving_config=serving_config,
                    query=query,
                    page_size=top_k,
                )
                response = client.search(request=request)
                cloud_matches: list[dict[str, Any]] = []
                for idx, result in enumerate(response.results):
                    data = dict(result.document.struct_data)
                    cloud_matches.append(
                        {
                            "runbook_id": str(data.get("runbook_id", f"RB-CLOUD-{idx}")),
                            "title": str(data.get("title", "Cloud SRE Runbook")),
                            "relevance_score": round(max(0.1, 0.95 - idx * 0.1), 4),
                            "root_cause_pattern": str(
                                data.get("root_cause_pattern", "Vertex AI Search matched pattern")
                            ),
                            "recommended_mitigation_steps": list(
                                data.get("recommended_mitigation_steps", ["Follow standard runbook"])
                            ),
                            "requires_human_approval_for_rollback": bool(
                                data.get("requires_human_approval_for_rollback", True)
                            ),
                            "retrieval_backend": "vertex_ai_search",
                        }
                    )
                if cloud_matches:
                    return cloud_matches[:top_k]
            except Exception:
                pass

        scored: list[dict[str, Any]] = []
        for rb in self._runbooks:
            corpus = f"{rb['title']} {rb['keywords']} {rb['root_cause_pattern']}"
            score = self._cosine_similarity(query, corpus)
            scored.append(
                {
                    "runbook_id": rb["runbook_id"],
                    "title": rb["title"],
                    "relevance_score": max(0.05, score),
                    "root_cause_pattern": rb["root_cause_pattern"],
                    "recommended_mitigation_steps": list(rb["recommended_mitigation_steps"]),
                    "requires_human_approval_for_rollback": rb[
                        "requires_human_approval_for_rollback"
                    ],
                    "retrieval_backend": "local_vector_index",
                }
            )
        scored.sort(key=lambda item: float(item["relevance_score"]), reverse=True)
        return scored[:top_k]


class AsyncMemoryConsolidator:
    """Executes expensive post-incident memory extraction and storage asynchronously in the background."""

    def __init__(self, session_store: PersistentSessionStore) -> None:
        self.session_store = session_store
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._active_tasks: set[asyncio.Task[Any]] = set()

    async def _process_item(self, item: dict[str, Any]) -> str:
        """Background coroutine that synthesizes and writes consolidated memory to SQLite."""
        await asyncio.sleep(0.005)
        consolidated_lesson = (
            f"[INCIDENT_POSTMORTEM:{item['service_name']}] "
            f"Summary: {item['incident_summary']} | "
            f"Verified Resolution: {'; '.join(item['resolution_steps'])}"
        )
        return await asyncio.to_thread(
            self.session_store.store_consolidated_memory,
            item["session_id"],
            item["service_name"],
            consolidated_lesson,
            item["resolution_steps"],
        )

    async def enqueue_consolidation(
        self,
        session_id: str,
        service_name: str,
        incident_summary: str,
        resolution_steps: list[str],
    ) -> str:
        """Schedule an asynchronous background task to consolidate incident memory without UI blocking."""
        task_id = f"memtask-{uuid.uuid4().hex[:10]}"
        payload = {
            "task_id": task_id,
            "session_id": session_id,
            "service_name": service_name,
            "incident_summary": incident_summary,
            "resolution_steps": resolution_steps,
        }
        await self._queue.put(payload)

        async def _runner() -> None:
            work_item = await self._queue.get()
            try:
                await self._process_item(work_item)
            finally:
                self._queue.task_done()

        bg_task = asyncio.create_task(_runner(), name=f"consolidate-{task_id}")
        self._active_tasks.add(bg_task)
        bg_task.add_done_callback(self._active_tasks.discard)
        return task_id

    async def wait_for_all_pending(self) -> None:
        """Wait for all queued background memory consolidation tasks to complete."""
        await self._queue.join()
        if self._active_tasks:
            await asyncio.gather(*list(self._active_tasks), return_exceptions=True)
