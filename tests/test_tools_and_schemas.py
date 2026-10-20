"""Unit tests for explicit JSON schemas and SRE tool interfaces."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

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


def test_service_health_query_input_strict_validation() -> None:
    """Verify strict Pydantic schema validation for service health queries."""
    valid = ServiceHealthQueryInput(
        service_name="checkout-service",
        region="us-central1",
        window_minutes=15,
    )
    assert valid.service_name == "checkout-service"
    assert valid.window_minutes == 15

    # Unknown fields must be rejected (extra='forbid')
    with pytest.raises(ValidationError):
        ServiceHealthQueryInput(
            service_name="checkout-service",
            region="us-central1",
            window_minutes=15,
            unexpected_field="disallowed",  # type: ignore[call-arg]
        )

    # Out-of-bounds window_minutes must be rejected
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
