"""Unit tests for PII redaction, structured JSON logging, Intent vs. Outcome capture, and OTel tracing."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from sre_agent.observability import (
    IntentOutcomeTracker,
    PIIRedactor,
    StructuredJsonLogger,
    TracingManager,
)


def test_pii_redactor_scrubs_emails_phones_ssns_keys_and_ips() -> None:
    """Verify PIIRedactor masks all sensitive PII entities before storage or logging."""
    redactor = PIIRedactor(enable_cloud_dlp=False)
    synthetic_api_key = "AIza" + "SyD_synthetic_unit_test_key_00000"
    raw_text = (
        "Customer jane.doe@example.org called from 415-555-0199 with SSN 123-45-6789 "
        f"and card 4532-0151-1283-0366 from IP 192.168.10.42 using key {synthetic_api_key}."
    )
    scrubbed = redactor.redact_text(raw_text)

    assert "jane.doe@example.org" not in scrubbed
    assert "415-555-0199" not in scrubbed
    assert "123-45-6789" not in scrubbed
    assert "4532-0151-1283-0366" not in scrubbed
    assert "192.168.10.42" not in scrubbed
    assert "AIzaSyD" not in scrubbed

    assert "[REDACTED_EMAIL]" in scrubbed
    assert "[REDACTED_PHONE]" in scrubbed
    assert "[REDACTED_SSN]" in scrubbed
    assert "[REDACTED_CREDIT_CARD]" in scrubbed
    assert "[REDACTED_IPV4]" in scrubbed
    assert "[REDACTED_API_KEY]" in scrubbed


def test_pii_redactor_invokes_google_cloud_dlp_when_configured() -> None:
    """Verify PIIRedactor integrates with Google Cloud DLP deidentify_content API."""
    mock_dlp = MagicMock()
    mock_response = MagicMock()
    mock_response.item.value = "User [DLP_REDACTED] triggered alert"
    mock_dlp.deidentify_content.return_value = mock_response

    redactor = PIIRedactor(
        project_id="demo-public-project",
        enable_cloud_dlp=True,
        dlp_client=mock_dlp,
    )
    result = redactor.redact_text("User alice@example.com triggered alert")
    assert mock_dlp.deidentify_content.called
    assert "[DLP_REDACTED]" in result


def test_structured_json_logger_emits_single_line_sanitized_json() -> None:
    """Verify StructuredJsonLogger outputs single-line JSON with PII scrubbed."""
    logger = StructuredJsonLogger(service_name="cloud-sre-agent")
    line = logger.log_event(
        event_type="ALERT_RECEIVED",
        message="Alert from operator bob@example.com on checkout-service",
        session_id="sess-001",
        metadata={"contact_phone": "650-555-1234", "service": "checkout-service"},
    )

    assert "\n" not in line
    parsed = json.loads(line)
    assert parsed["event_type"] == "ALERT_RECEIVED"
    assert parsed["session_id"] == "sess-001"
    assert "bob@example.com" not in parsed["message"]
    assert "[REDACTED_EMAIL]" in parsed["message"]
    assert parsed["metadata"]["contact_phone"] == "[REDACTED_PHONE]"


def test_intent_vs_outcome_tracker_records_paired_audit_trail() -> None:
    """Verify IntentOutcomeTracker captures both intended action and actual outcome."""
    logger = StructuredJsonLogger(service_name="cloud-sre-agent")
    tracker = IntentOutcomeTracker(logger=logger)

    intent_id = tracker.record_intent(
        session_id="sess-100",
        agent_name="TelemetryTriageAgent",
        tool_name="query_service_health_metrics",
        intended_action="Query p95/p99 latency and 5xx error rate for checkout-service",
        parameters={"service_name": "checkout-service", "window_minutes": 15},
    )

    outcome_record = tracker.record_outcome(
        intent_id=intent_id,
        actual_outcome="Retrieved metrics: p95=840ms, error_rate=14.2%, slo_breached=True",
        status="SUCCESS",
        output_summary={"slo_breached": True, "error_rate_percent": 14.2},
    )

    assert outcome_record["intent_id"] == intent_id
    assert outcome_record["intended_action"].startswith("Query p95/p99 latency")
    assert outcome_record["actual_outcome"].startswith("Retrieved metrics:")
    assert outcome_record["status"] == "SUCCESS"
    assert outcome_record["latency_ms"] >= 0.0

    history = tracker.get_session_audit_trail("sess-100")
    assert len(history) == 1
    assert history[0]["intent_id"] == intent_id


def test_opentelemetry_tracing_links_parent_and_child_spans() -> None:
    """Verify OpenTelemetry TracingManager links agent and tool spans in a single trace."""
    tracing = TracingManager(service_name="cloud-sre-agent")
    tracing.clear_exported_spans()

    with tracing.start_span(
        "incident_response_turn",
        attributes={"session.id": "sess-otel-1", "incident.service": "checkout-service"},
    ) as parent_span:
        with tracing.start_span(
            "tool.query_service_health_metrics",
            attributes={"tool.name": "query_service_health_metrics"},
        ) as child_span:
            child_span.set_attribute("tool.status", "OK")
        parent_span.set_attribute("turn.status", "COMPLETED")

    spans = tracing.get_exported_spans()
    assert len(spans) == 2
    child, parent = spans[0], spans[1]
    assert child.name == "tool.query_service_health_metrics"
    assert parent.name == "incident_response_turn"
    assert child.context.trace_id == parent.context.trace_id
    assert child.parent is not None
    assert child.parent.span_id == parent.context.span_id
