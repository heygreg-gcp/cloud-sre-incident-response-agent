"""Observability, Distributed Tracing, Intent-vs-Outcome Auditing, and PII Redaction.

Implements the four pillars of Category 4 (Observability & Tracing):
1. Structured JSON Logging (`StructuredJsonLogger`)
2. Intent vs. Outcome Capture (`IntentOutcomeTracker`)
3. Distributed Tracing with OpenTelemetry (`TracingManager`)
4. Active PII Redaction using Google Cloud DLP API + deterministic regex (`PIIRedactor`)
"""

from __future__ import annotations

import contextlib
import datetime
import io
import json
import logging
import re
import time
import uuid
from typing import Any, Iterator

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pythonjsonlogger.json import JsonFormatter


class PIIRedactor:
    """Scrubs sensitive PII and secrets from logs, prompts, and memory payloads.

    Integrates with Google Cloud Data Loss Prevention (`google.cloud.dlp_v2`) when
    enabled and always applies a deterministic multi-pattern regex pass so no PII
    ever leaks even in offline or local evaluation environments.
    """

    _PATTERNS: list[tuple[re.Pattern[str], str]] = [
        # Google / generic API keys & bearer tokens
        (
            re.compile(r"\b(?:AIza[0-9A-Za-z\-_]{20,}|ya29\.[0-9A-Za-z\-_]+|sk-[0-9A-Za-z]{20,})\b"),
            "[REDACTED_API_KEY]",
        ),
        # Credit card numbers (16 digits with dashes or spaces)
        (
            re.compile(r"\b(?:\d{4}[-\s]){3}\d{4}\b"),
            "[REDACTED_CREDIT_CARD]",
        ),
        # US Social Security Numbers
        (
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            "[REDACTED_SSN]",
        ),
        # Email addresses
        (
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            "[REDACTED_EMAIL]",
        ),
        # US Phone numbers
        (
            re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"),
            "[REDACTED_PHONE]",
        ),
        # IPv4 addresses
        (
            re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            "[REDACTED_IPV4]",
        ),
    ]

    def __init__(
        self,
        project_id: str | None = None,
        enable_cloud_dlp: bool = False,
        dlp_client: Any | None = None,
    ) -> None:
        self.project_id = project_id
        self.enable_cloud_dlp = enable_cloud_dlp
        self._dlp_client = dlp_client

    def _get_dlp_client(self) -> Any | None:
        if self._dlp_client is not None:
            return self._dlp_client
        if not self.enable_cloud_dlp or not self.project_id:
            return None
        try:
            from google.cloud import dlp_v2

            self._dlp_client = dlp_v2.DlpServiceClient()
            return self._dlp_client
        except Exception:
            return None

    def redact_text(self, text: str) -> str:
        """Redact sensitive PII from an arbitrary string."""
        if not text:
            return text

        sanitized = text
        dlp_client = self._get_dlp_client()
        if dlp_client is not None and self.project_id:
            try:
                parent = f"projects/{self.project_id}/locations/global"
                inspect_config = {
                    "info_types": [
                        {"name": "EMAIL_ADDRESS"},
                        {"name": "PHONE_NUMBER"},
                        {"name": "US_SOCIAL_SECURITY_NUMBER"},
                        {"name": "CREDIT_CARD_NUMBER"},
                        {"name": "IP_ADDRESS"},
                    ]
                }
                deidentify_config = {
                    "info_type_transformations": {
                        "transformations": [
                            {
                                "primitive_transformation": {
                                    "replace_config": {
                                        "new_value": {"string_value": "[DLP_REDACTED]"}
                                    }
                                }
                            }
                        ]
                    }
                }
                response = dlp_client.deidentify_content(
                    request={
                        "parent": parent,
                        "inspect_config": inspect_config,
                        "deidentify_config": deidentify_config,
                        "item": {"value": sanitized},
                    }
                )
                sanitized = str(response.item.value)
            except Exception:
                # Fall through to deterministic local regex scrubbing
                pass

        for pattern, replacement in self._PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized

    def redact_value(self, value: Any) -> Any:
        """Recursively redact PII across strings, dictionaries, and lists."""
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, dict):
            return {str(k): self.redact_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.redact_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.redact_value(item) for item in value)
        return value


class StructuredJsonLogger:
    """Emits single-line, PII-redacted structured JSON telemetry records."""

    def __init__(
        self,
        service_name: str = "cloud-sre-incident-response-agent",
        redactor: PIIRedactor | None = None,
    ) -> None:
        self.service_name = service_name
        self.redactor = redactor or PIIRedactor(enable_cloud_dlp=False)
        self._records: list[dict[str, Any]] = []

        self._logger = logging.getLogger(f"sre_agent.{service_name}.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        self._stream = io.StringIO()
        handler = logging.StreamHandler(self._stream)
        formatter = JsonFormatter("%(timestamp)s %(level)s %(name)s %(message)s")
        handler.setFormatter(formatter)
        self._logger.handlers = [handler]

    def log_event(
        self,
        event_type: str,
        message: str,
        session_id: str = "default-session",
        level: str = "INFO",
        trace_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Serialize a structured telemetry record as a single-line JSON string."""
        sanitized_message = self.redactor.redact_text(message)
        sanitized_metadata = self.redactor.redact_value(metadata or {})

        payload: dict[str, Any] = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "service": self.service_name,
            "level": level,
            "event_type": event_type,
            "session_id": session_id,
            "trace_id": trace_id or "no-active-trace",
            "message": sanitized_message,
            "metadata": sanitized_metadata,
        }
        self._records.append(payload)
        single_line = json.dumps(payload, separators=(",", ":"), sort_keys=False)
        extra_fields = {k: v for k, v in payload.items() if k != "message"}
        self._logger.info(sanitized_message, extra=extra_fields)
        return single_line

    def get_records(self) -> list[dict[str, Any]]:
        """Return all structured log records captured by this logger instance."""
        return list(self._records)


class IntentOutcomeTracker:
    """Captures explicit pre-execution Intent and post-execution Outcome audit records."""

    def __init__(self, logger: StructuredJsonLogger | None = None) -> None:
        self.logger = logger or StructuredJsonLogger()
        self._pending_intents: dict[str, dict[str, Any]] = {}
        self._completed_audits: list[dict[str, Any]] = []

    def record_intent(
        self,
        session_id: str,
        agent_name: str,
        tool_name: str,
        intended_action: str,
        parameters: dict[str, Any],
    ) -> str:
        """Log the agent's intended action before invoking a tool or sub-agent."""
        intent_id = f"intent-{uuid.uuid4().hex[:12]}"
        sanitized_params = self.logger.redactor.redact_value(parameters)
        sanitized_intent = self.logger.redactor.redact_text(intended_action)

        intent_entry = {
            "intent_id": intent_id,
            "session_id": session_id,
            "agent_name": agent_name,
            "tool_name": tool_name,
            "intended_action": sanitized_intent,
            "parameters": sanitized_params,
            "started_at_monotonic": time.monotonic(),
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self._pending_intents[intent_id] = intent_entry

        self.logger.log_event(
            event_type="AGENT_INTENT_RECORDED",
            message=f"[{agent_name}] Intended action on {tool_name}: {sanitized_intent}",
            session_id=session_id,
            metadata={
                "intent_id": intent_id,
                "agent_name": agent_name,
                "tool_name": tool_name,
                "intended_action": sanitized_intent,
                "parameters": sanitized_params,
            },
        )
        return intent_id

    def record_outcome(
        self,
        intent_id: str,
        actual_outcome: str,
        status: str,
        output_summary: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Log the actual outcome after tool execution and pair it with the original intent."""
        intent_entry = self._pending_intents.get(
            intent_id,
            {
                "intent_id": intent_id,
                "session_id": "unknown-session",
                "agent_name": "UnknownAgent",
                "tool_name": "unknown_tool",
                "intended_action": "Unregistered intent",
                "parameters": {},
                "started_at_monotonic": time.monotonic(),
            },
        )
        elapsed_ms = round(
            max(0.0, (time.monotonic() - float(intent_entry["started_at_monotonic"])) * 1000.0),
            3,
        )
        sanitized_outcome = self.logger.redactor.redact_text(actual_outcome)
        sanitized_summary = self.logger.redactor.redact_value(output_summary or {})

        audit_record: dict[str, Any] = {
            "intent_id": intent_id,
            "session_id": intent_entry["session_id"],
            "agent_name": intent_entry["agent_name"],
            "tool_name": intent_entry["tool_name"],
            "intended_action": intent_entry["intended_action"],
            "parameters": intent_entry["parameters"],
            "actual_outcome": sanitized_outcome,
            "status": status,
            "latency_ms": elapsed_ms,
            "output_summary": sanitized_summary,
            "completed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self._completed_audits.append(audit_record)

        self.logger.log_event(
            event_type="AGENT_OUTCOME_RECORDED",
            message=(
                f"[{intent_entry['agent_name']}] Outcome for {intent_entry['tool_name']} "
                f"({status} in {elapsed_ms}ms): {sanitized_outcome}"
            ),
            session_id=str(intent_entry["session_id"]),
            metadata=audit_record,
        )
        return audit_record

    def get_session_audit_trail(self, session_id: str) -> list[dict[str, Any]]:
        """Return all paired Intent-vs-Outcome records for a given session."""
        return [
            record
            for record in self._completed_audits
            if record.get("session_id") == session_id
        ]


class TracingManager:
    """OpenTelemetry distributed tracing manager linking agent turns and tool calls."""

    def __init__(self, service_name: str = "cloud-sre-incident-response-agent") -> None:
        self.service_name = service_name
        resource = Resource.create({"service.name": service_name})
        self._provider = TracerProvider(resource=resource)
        self._memory_exporter = InMemorySpanExporter()
        self._provider.add_span_processor(SimpleSpanProcessor(self._memory_exporter))
        self._tracer = self._provider.get_tracer(service_name)

    @contextlib.contextmanager
    def start_span(
        self,
        name: str,
        attributes: dict[str, Any] | None = None,
    ) -> Iterator[trace.Span]:
        """Start an OpenTelemetry span linked to the current active parent span."""
        with self._tracer.start_as_current_span(name) as span:
            if attributes:
                for key, value in attributes.items():
                    if isinstance(value, (str, bool, int, float)):
                        span.set_attribute(key, value)
                    else:
                        span.set_attribute(key, json.dumps(value, default=str))
            yield span

    def get_exported_spans(self) -> list[ReadableSpan]:
        """Return all finished OpenTelemetry spans captured in memory."""
        return list(self._memory_exporter.get_finished_spans())

    def clear_exported_spans(self) -> None:
        """Clear the in-memory span buffer."""
        self._memory_exporter.clear()


DEFAULT_REDACTOR = PIIRedactor(enable_cloud_dlp=False)
DEFAULT_LOGGER = StructuredJsonLogger(redactor=DEFAULT_REDACTOR)
DEFAULT_INTENT_TRACKER = IntentOutcomeTracker(logger=DEFAULT_LOGGER)
DEFAULT_TRACING = TracingManager()
