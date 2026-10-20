"""Unit tests for explicit JSON schemas and SRE tool interfaces."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sre_agent.guardrails import DEFAULT_APPROVAL_GATE
from sre_agent.schemas import (
    CreateIncidentTicketInput,
    CreateIncidentTicketOutput,
    DeploymentCorrelationInput,
    DeploymentCorrelationOutput,
    ErrorLogAnalysisInput,
    ErrorLogAnalysisOutput,
    GuidedToolError,
    IncidentAssessmentReport,
    ProductionRollbackInput,
    ProductionRollbackOutput,
    RunbookSearchInput,
    RunbookSearchOutput,
    ServiceHealthMetricsOutput,
    ServiceHealthQueryInput,
)
from sre_agent.tools import (
    ALL_SRE_TOOLS,
    analyze_error_log_anomalies,
    correlate_deployment_change_events,
    create_critical_incident_ticket,
    execute_production_rollback,
    query_service_health_metrics,
    search_incident_runbooks,
)


def test_service_health_query_input_strict_validation() -> None:
    """Verify strict Pydantic schema validation for service health queries."""
    valid = ServiceHealthQueryInput(
        service_name="checkout-service",
        region="us-central1",
        window_minutes=15,
    )
    assert valid.service_name == "checkout-service"
    assert valid.window_minutes == 15

    with pytest.raises(ValidationError):
        ServiceHealthQueryInput(
            service_name="checkout-service",
            region="us-central1",
            window_minutes=15,
            unexpected_field="disallowed",  # type: ignore[call-arg]
        )

    with pytest.raises(ValidationError):
        ServiceHealthQueryInput(
            service_name="checkout-service",
            region="us-central1",
            window_minutes=0,
        )


def test_guided_tool_error_schema_includes_recovery_instructions() -> None:
    """Verify GuidedToolError provides structured recovery guidance to the LLM."""
    err = GuidedToolError(
        error_code="SERVICE_NOT_FOUND",
        failed_tool="query_service_health_metrics",
        message="Service 'unknown-svc' is not registered in the telemetry catalog.",
        recovery_instructions=(
            "Retry query_service_health_metrics using one of the supported "
            "production service names: checkout-service, payment-gateway, auth-service."
        ),
        suggested_next_tool="search_incident_runbooks",
        retryable=True,
    )
    dumped = err.model_dump()
    assert dumped["status"] == "ERROR"
    assert dumped["error_code"] == "SERVICE_NOT_FOUND"
    assert "checkout-service" in dumped["recovery_instructions"]
    assert dumped["suggested_next_tool"] == "search_incident_runbooks"


def test_all_tool_input_output_schemas_generate_strict_json_schema() -> None:
    """Verify every tool input, output, and assessment report exports valid JSON Schema."""
    models = [
        ServiceHealthQueryInput,
        ServiceHealthMetricsOutput,
        ErrorLogAnalysisInput,
        ErrorLogAnalysisOutput,
        RunbookSearchInput,
        RunbookSearchOutput,
        DeploymentCorrelationInput,
        DeploymentCorrelationOutput,
        CreateIncidentTicketInput,
        CreateIncidentTicketOutput,
        ProductionRollbackInput,
        ProductionRollbackOutput,
        IncidentAssessmentReport,
    ]
    for model_cls in models:
        schema = model_cls.model_json_schema()
        assert "properties" in schema
        assert schema.get("additionalProperties") is False


def test_all_tools_have_comprehensive_docstrings_and_descriptive_names() -> None:
    """Verify Category 1 criteria: Comprehensive Tool Docstrings & Descriptive Naming."""
    assert len(ALL_SRE_TOOLS) == 6
    for tool_fn in ALL_SRE_TOOLS:
        doc = tool_fn.__doc__ or ""
        assert len(doc) >= 200, f"Tool {tool_fn.__name__} docstring is too short"
        assert "Args:" in doc
        assert "Returns:" in doc
        assert len(tool_fn.__name__.split("_")) >= 3


def test_query_service_health_metrics_and_guided_error_on_unknown_service() -> None:
    """Verify query_service_health_metrics returns golden signals or guided recovery error."""
    res = query_service_health_metrics(
        service_name="checkout-service",
        region="us-central1",
        window_minutes=15,
    )
    assert res["status"] == "OK"
    assert res["slo_breached"] is True
    assert res["error_rate_percent"] > 5.0

    err = query_service_health_metrics(
        service_name="nonexistent-service",
        region="us-central1",
        window_minutes=15,
    )
    assert err["status"] == "ERROR"
    assert err["error_code"] == "SERVICE_NOT_FOUND"
    assert "checkout-service" in err["recovery_instructions"]


def test_analyze_error_log_anomalies_and_correlate_deployments() -> None:
    """Verify log clustering and deployment correlation tools return schema-valid payloads."""
    logs = analyze_error_log_anomalies(
        service_name="checkout-service",
        severity_filter="ERROR",
        max_clusters=3,
    )
    assert logs["status"] == "OK"
    assert logs["total_error_events"] > 0
    assert len(logs["top_clusters"]) >= 1

    deployments = correlate_deployment_change_events(
        service_name="checkout-service",
        lookback_hours=6,
    )
    assert deployments["status"] == "OK"
    assert deployments["suspect_change_detected"] is True
    assert deployments["events"][0]["release_version"] == "v2.5.0-canary"


def test_search_incident_runbooks_and_create_critical_incident_ticket() -> None:
    """Verify runbook search and PII-sanitized critical incident ticket creation."""
    runbooks = search_incident_runbooks(
        query="checkout-service 5xx error spike after canary release",
        top_k=2,
    )
    assert runbooks["status"] == "OK"
    assert runbooks["matches"][0]["runbook_id"] == "RB-101-CANARY-ROLLBACK"

    ticket = create_critical_incident_ticket(
        service_name="checkout-service",
        severity="SEV1",
        title="Checkout 5xx Surge reported by user@example.com",
        root_cause_hypothesis="Canary release v2.5.0-canary introduced NullPointerException",
        commander_handle="sre-oncall-primary",
    )
    assert ticket["status"] == "OK"
    assert ticket["ticket_id"].startswith("INC-")
    assert "user@example.com" not in ticket["sanitized_title"]
    assert "[REDACTED_EMAIL]" in ticket["sanitized_title"]


def test_execute_production_rollback_enforces_hitl_and_succeeds_with_token() -> None:
    """Verify execute_production_rollback halts without token and succeeds with valid HITL token."""
    halted = execute_production_rollback(
        service_name="checkout-service",
        target_stable_version="v2.4.1",
        reason="Rollback faulty canary v2.5.0-canary after 14.2% HTTP 500 error spike",
        human_approval_token=None,
    )
    assert halted["status"] == "PENDING_HUMAN_APPROVAL"
    assert halted["error_code"] == "HUMAN_APPROVAL_REQUIRED"

    token = DEFAULT_APPROVAL_GATE.issue_approval_token(
        service_name="checkout-service",
        action="execute_production_rollback",
        target_version="v2.4.1",
    )
    completed = execute_production_rollback(
        service_name="checkout-service",
        target_stable_version="v2.4.1",
        reason="Rollback faulty canary v2.5.0-canary after 14.2% HTTP 500 error spike",
        human_approval_token=token,
    )
    assert completed["status"] == "OK"
    assert completed["restored_version"] == "v2.4.1"
    assert completed["verification_status"] == "HEALTHY_POST_ROLLBACK"
