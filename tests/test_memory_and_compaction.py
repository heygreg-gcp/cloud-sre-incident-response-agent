"""Unit tests for history compaction, persistent session state, Vertex AI Search, and async memory operations."""

from __future__ import annotations

import pathlib

import pytest

from sre_agent.memory import (
    AsyncMemoryConsolidator,
    HistoryCompactor,
    PersistentSessionStore,
    VertexSearchKnowledgeStore,
)


def test_history_compactor_enforces_token_budget_and_summarizes_evicted_turns() -> None:
    """Verify HistoryCompactor compacts long histories via sliding window + summary."""
    compactor = HistoryCompactor(max_token_budget=60, recent_turns_to_keep=2)
    turns = [
        {"role": "user", "content": "Alert fired on checkout-service with high 500 rate in us-central1."},
        {"role": "assistant", "content": "Queried metrics: error_rate=14.2%, p95=840ms, release=v2.5.0-canary."},
        {"role": "user", "content": "Check error logs and recent deployments for checkout-service."},
        {"role": "assistant", "content": "Found NullPointerException in PaymentTokenValidator after v2.5.0-canary rollout."},
        {"role": "user", "content": "Prepare rollback plan to v2.4.1 and open SEV1 incident ticket."},
    ]

    compacted = compactor.compact_history(turns)
    # 1 summary message + 2 most recent turns = 3 entries
    assert len(compacted) == 3
    assert compacted[0]["role"] == "system"
    assert "[COMPACTED_HISTORY_SUMMARY]" in compacted[0]["content"]
    assert "checkout-service" in compacted[0]["content"]
    assert compacted[-1]["content"].startswith("Prepare rollback plan")

    cache_cfg = compactor.build_vertex_context_cache_config(
        system_instruction="Constitutional SRE prompt",
        ttl_seconds=3600,
    )
    assert cache_cfg["ttl"] == "3600s"
    assert cache_cfg["model"] == "gemini-2.5-pro"


def test_persistent_session_store_persists_pii_redacted_turns_and_memories(
    tmp_path: pathlib.Path,
) -> None:
    """Verify PersistentSessionStore writes and retrieves turns across instances using parameterized SQLite."""
    db_file = tmp_path / "sre_sessions.sqlite3"
    store = PersistentSessionStore(db_path=str(db_file))

    store.append_turn(
        session_id="sess-persist-01",
        role="user",
        content="On-call engineer alice@example.com reported 503 spike on payment-gateway",
        metadata={"service": "payment-gateway"},
    )
    store.append_turn(
        session_id="sess-persist-01",
        role="assistant",
        content="Initiated telemetry triage for payment-gateway.",
        metadata={"stage": "triage"},
    )

    # Re-open a fresh store instance against the same SQLite file to verify persistence
    reopened = PersistentSessionStore(db_path=str(db_file))
    history = reopened.get_session_turns("sess-persist-01")
    assert len(history) == 2
    assert "alice@example.com" not in history[0]["content"]
    assert "[REDACTED_EMAIL]" in history[0]["content"]
    assert history[1]["role"] == "assistant"


def test_vertex_search_knowledge_store_retrieves_relevant_sre_runbooks() -> None:
    """Verify VertexSearchKnowledgeStore ranks relevant SRE runbooks accurately."""
    kb = VertexSearchKnowledgeStore(project_id=None, data_store_id=None)
    results = kb.search_runbooks(
        query="checkout-service 5xx error spike after canary deployment release",
        top_k=2,
    )
    assert len(results) == 2
    assert results[0]["runbook_id"] == "RB-101-CANARY-ROLLBACK"
    assert results[0]["relevance_score"] > 0.2


@pytest.mark.asyncio
async def test_async_memory_consolidator_processes_memories_in_background(
    tmp_path: pathlib.Path,
) -> None:
    """Verify AsyncMemoryConsolidator consolidates episodic memories asynchronously without blocking."""
    db_file = tmp_path / "async_memory.sqlite3"
    store = PersistentSessionStore(db_path=str(db_file))
    consolidator = AsyncMemoryConsolidator(session_store=store)

    task_id = await consolidator.enqueue_consolidation(
        session_id="sess-async-99",
        service_name="auth-service",
        incident_summary=(
            "Redis connection pool exhaustion caused by leaked connections in v1.9.0; "
            "reported by pager contact 415-555-0144."
        ),
        resolution_steps=[
            "Rolled back auth-service to v1.8.4",
            "Verified connection pool utilization dropped below 35%",
        ],
    )
    assert task_id.startswith("memtask-")

    await consolidator.wait_for_all_pending()
    memories = store.search_consolidated_memories(service_name="auth-service")
    assert len(memories) == 1
    assert memories[0]["service_name"] == "auth-service"
    assert "415-555-0144" not in memories[0]["consolidated_lesson"]
    assert "[REDACTED_PHONE]" in memories[0]["consolidated_lesson"]
