"""Strict Pydantic JSON Schemas for tool inputs, tool outputs, and agent reports.

This module enforces explicit input and output validation across all agent tools
and LLM structured responses, preventing malformed parameters and providing
guided recovery instructions when validation or operational errors occur.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictSchemaModel(BaseModel):
    """Base Pydantic model enforcing strict JSON Schema constraints."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class GuidedToolError(StrictSchemaModel):
    """Structured error payload returned to the LLM with actionable recovery steps."""

    status: Literal["ERROR", "PENDING_HUMAN_APPROVAL"] = Field(
        default="ERROR",
        description="Execution status discriminator indicating error or approval hold.",
    )
    error_code: str = Field(
        ...,
        min_length=3,
        max_length=64,
        description="Machine-readable error classification code.",
    )
    failed_tool: str = Field(
        ...,
        min_length=3,
        max_length=128,
        description="Name of the tool function where the failure occurred.",
    )
    message: str = Field(
        ...,
        min_length=5,
        description="Human-readable explanation of why the tool invocation failed.",
    )
    recovery_instructions: str = Field(
        ...,
        min_length=10,
        description="Step-by-step instructions telling the LLM how to recover or retry.",
    )
    suggested_next_tool: str | None = Field(
        default=None,
        description="Recommended next tool for the agent to call to resolve the issue.",
    )
    retryable: bool = Field(
        default=True,
        description="Whether the LLM should retry after adjusting arguments.",
    )


class ServiceHealthQueryInput(StrictSchemaModel):
    """Input schema for querying golden-signal service health telemetry."""

    service_name: str = Field(
        ...,
        pattern=r"^[a-z0-9-]+$",
        min_length=3,
        max_length=64,
        description="Canonical kebab-case production microservice identifier.",
    )
    region: str = Field(
        default="us-central1",
        pattern=r"^[a-z]+-[a-z]+[0-9]$",
        description="Cloud region hosting the target service deployment.",
    )
    window_minutes: int = Field(
        default=15,
        ge=1,
        le=1440,
        description="Lookback observation window in minutes (1 to 1440).",
    )


class ServiceHealthMetricsOutput(StrictSchemaModel):
    """Output schema containing golden-signal telemetry metrics for a service."""

    status: Literal["OK"] = "OK"
    service_name: str = Field(..., description="Target production service identifier.")
    region: str = Field(..., description="Evaluated cloud region.")
    window_minutes: int = Field(..., description="Evaluated lookback window in minutes.")
    p95_latency_ms: float = Field(..., ge=0.0, description="95th percentile latency in ms.")
    p99_latency_ms: float = Field(..., ge=0.0, description="99th percentile latency in ms.")
    error_rate_percent: float = Field(
        ..., ge=0.0, le=100.0, description="HTTP 5xx error percentage."
    )
    saturation_cpu_percent: float = Field(
        ..., ge=0.0, le=100.0, description="Container CPU utilization percentage."
    )
    requests_per_second: float = Field(..., ge=0.0, description="Current request throughput.")
    slo_breached: bool = Field(..., description="True if error rate or latency breaches SLO.")
    active_release_version: str = Field(..., description="Currently serving release tag.")


class ErrorLogAnalysisInput(StrictSchemaModel):
    """Input schema for clustering error log anomalies from Cloud Logging."""

    service_name: str = Field(
        ...,
        pattern=r"^[a-z0-9-]+$",
        min_length=3,
        max_length=64,
        description="Canonical kebab-case production microservice identifier.",
    )
    severity_filter: Literal["WARNING", "ERROR", "CRITICAL"] = Field(
        default="ERROR",
        description="Minimum log severity threshold to inspect.",
    )
    max_clusters: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum number of top error signature clusters to return.",
    )


class ErrorClusterEntry(StrictSchemaModel):
    """Single clustered error signature extracted from service logs."""

    signature: str = Field(..., description="Normalized error signature or exception class.")
    occurrence_count: int = Field(..., ge=1, description="Number of matching log entries.")
    sample_message: str = Field(..., description="PII-sanitized representative log message.")
    suspected_component: str = Field(..., description="Subsystem associated with the error.")


class ErrorLogAnalysisOutput(StrictSchemaModel):
    """Output schema for error log anomaly clustering."""

    status: Literal["OK"] = "OK"
    service_name: str = Field(..., description="Evaluated microservice identifier.")
    total_error_events: int = Field(..., ge=0, description="Total error log events in window.")
    top_clusters: list[ErrorClusterEntry] = Field(
        ..., description="Ranked list of dominant error log clusters."
    )


class RunbookSearchInput(StrictSchemaModel):
    """Input schema for searching SRE remediation runbooks via Vertex AI Search."""

    query: str = Field(
        ...,
        min_length=3,
        max_length=512,
        description="Symptom, error signature, or service query for runbook retrieval.",
    )
    top_k: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum number of runbook documents to return.",
    )


class RunbookDocumentMatch(StrictSchemaModel):
    """Matched SRE runbook document with similarity score and remediation steps."""

    runbook_id: str = Field(..., description="Unique runbook identifier.")
    title: str = Field(..., description="Human-readable runbook title.")
    relevance_score: float = Field(
        ..., ge=0.0, le=1.0, description="Normalized semantic relevance score."
    )
    root_cause_pattern: str = Field(..., description="Known root cause pattern.")
    recommended_mitigation_steps: list[str] = Field(
        ..., description="Ordered list of verified SRE mitigation steps."
    )
    requires_human_approval_for_rollback: bool = Field(
        default=True,
        description="Whether executing the destructive remediation requires human sign-off.",
    )


class RunbookSearchOutput(StrictSchemaModel):
    """Output schema for runbook search results."""

    status: Literal["OK"] = "OK"
    query: str = Field(..., description="Executed search query.")
    retrieval_backend: Literal["vertex_ai_search", "local_vector_index"] = Field(
        ..., description="Backend knowledge store used to fulfill the query."
    )
    matches: list[RunbookDocumentMatch] = Field(
        ..., description="Ranked runbook matches."
    )


class DeploymentCorrelationInput(StrictSchemaModel):
    """Input schema for correlating recent deployments and config rollouts."""

    service_name: str = Field(
        ...,
        pattern=r"^[a-z0-9-]+$",
        min_length=3,
        max_length=64,
        description="Target production microservice identifier.",
    )
    lookback_hours: int = Field(
        default=6,
        ge=1,
        le=168,
        description="Lookback window in hours for change event correlation.",
    )


class ChangeEventRecord(StrictSchemaModel):
    """Single deployment or configuration change event."""

    change_id: str = Field(..., description="Deployment or rollout identifier.")
    timestamp_utc: str = Field(..., description="ISO-8601 timestamp of the deployment.")
    release_version: str = Field(..., description="Deployed artifact version.")
    previous_version: str = Field(..., description="Prior stable artifact version.")
    change_summary: str = Field(..., description="Sanitized summary of changes.")
    temporal_correlation_score: float = Field(
        ..., ge=0.0, le=1.0, description="Correlation score with incident onset."
    )


class DeploymentCorrelationOutput(StrictSchemaModel):
    """Output schema for deployment change correlation analysis."""

    status: Literal["OK"] = "OK"
    service_name: str = Field(..., description="Target production service identifier.")
    suspect_change_detected: bool = Field(
        ..., description="True if a high-correlation deployment change was found."
    )
    events: list[ChangeEventRecord] = Field(
        ..., description="Correlated deployment change events."
    )


class CreateIncidentTicketInput(StrictSchemaModel):
    """Input schema for opening a critical incident response ticket."""

    service_name: str = Field(
        ...,
        pattern=r"^[a-z0-9-]+$",
        min_length=3,
        max_length=64,
        description="Affected production service name.",
    )
    severity: Literal["SEV1", "SEV2", "SEV3"] = Field(
        ..., description="Incident severity classification."
    )
    title: str = Field(
        ...,
        min_length=5,
        max_length=200,
        description="Concise incident headline.",
    )
    root_cause_hypothesis: str = Field(
        ...,
        min_length=10,
        max_length=2000,
        description="Evidence-backed root-cause hypothesis.",
    )
    commander_handle: str = Field(
        default="sre-oncall-primary",
        min_length=3,
        max_length=64,
        description="Assigned incident commander role identifier (PII-free).",
    )


class CreateIncidentTicketOutput(StrictSchemaModel):
    """Output schema for a created incident ticket."""

    status: Literal["OK"] = "OK"
    ticket_id: str = Field(..., description="Generated incident tracking ID.")
    service_name: str = Field(..., description="Affected production service.")
    severity: Literal["SEV1", "SEV2", "SEV3"] = Field(..., description="Ticket severity.")
    sanitized_title: str = Field(..., description="PII-scrubbed ticket headline.")
    sanitized_hypothesis: str = Field(..., description="PII-scrubbed root-cause summary.")
    bridge_channel: str = Field(..., description="Assigned incident coordination channel.")


class ProductionRollbackInput(StrictSchemaModel):
    """Input schema for executing a high-stakes production release rollback."""

    service_name: str = Field(
        ...,
        pattern=r"^[a-z0-9-]+$",
        min_length=3,
        max_length=64,
        description="Target production microservice to roll back.",
    )
    target_stable_version: str = Field(
        ...,
        pattern=r"^v[0-9]+\.[0-9]+\.[0-9]+$",
        description="Verified stable semantic version tag to restore (e.g., v2.4.1).",
    )
    reason: str = Field(
        ...,
        min_length=10,
        max_length=500,
        description="Audit justification for rolling back production traffic.",
    )
    human_approval_token: str | None = Field(
        default=None,
        description="Explicit Human-in-the-Loop cryptographic approval token required for execution.",
    )


class ProductionRollbackOutput(StrictSchemaModel):
    """Output schema for a completed production rollback operation."""

    status: Literal["OK"] = "OK"
    rollback_id: str = Field(..., description="Unique rollback execution identifier.")
    service_name: str = Field(..., description="Service that was rolled back.")
    restored_version: str = Field(..., description="Restored stable release version.")
    previous_faulty_version: str = Field(..., description="Replaced faulty version.")
    verification_status: Literal["HEALTHY_POST_ROLLBACK"] = "HEALTHY_POST_ROLLBACK"
    approved_by_token_fingerprint: str = Field(
        ..., description="Audit hash of the HITL token."
    )


class IncidentAssessmentReport(StrictSchemaModel):
    """Structured final output schema produced by the Incident Response Coordinator."""

    incident_id: str = Field(..., description="Incident ticket identifier.")
    service_name: str = Field(..., description="Impacted production service.")
    severity: Literal["SEV1", "SEV2", "SEV3"] = Field(..., description="Incident severity.")
    slo_breached: bool = Field(..., description="Whether golden-signal SLOs were breached.")
    root_cause_summary: str = Field(..., description="Synthesized root-cause analysis.")
    matched_runbook_id: str = Field(..., description="Primary SRE runbook matched.")
    remediation_status: Literal[
        "AWAITING_HUMAN_APPROVAL",
        "ROLLED_BACK_AND_MITIGATED",
        "MONITORING_STABLE",
        "BLOCKED_BY_GUARDRAIL",
    ] = Field(..., description="Current remediation lifecycle state.")
    recommended_actions: list[str] = Field(
        ..., description="Ordered list of verified remediation actions."
    )
    routed_models_used: dict[str, str] = Field(
        ..., description="Map of sub-agent roles to the Gemini model tier used."
    )
    self_critique_score: float = Field(
        ..., ge=0.0, le=1.0, description="Evaluator-optimizer quality score."
    )
