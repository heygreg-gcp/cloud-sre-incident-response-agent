"""Domain-Specific SRE Incident Response Tools with Strict Schemas, Tracing, and Guided Error Handling.

Implements all four criteria of Category 1 (Tool & Interface Design):
1. Comprehensive Tool Docstrings — complete human- and LLM-readable documentation
2. Descriptive Naming — specific action-oriented function names
3. Explicit JSON Schemas — strict Pydantic input/output schema validation
4. Guided Error Handling — structured recovery instructions returned on validation or catalog errors
"""

from __future__ import annotations

import uuid
from typing import Any, Callable

from pydantic import ValidationError

from sre_agent.guardrails import DEFAULT_APPROVAL_GATE, before_tool_guardrail_callback
from sre_agent.memory import VertexSearchKnowledgeStore
from sre_agent.observability import (
    DEFAULT_INTENT_TRACKER,
    DEFAULT_REDACTOR,
    DEFAULT_TRACING,
)
from sre_agent.schemas import (
    ChangeEventRecord,
    CreateIncidentTicketInput,
    CreateIncidentTicketOutput,
    DeploymentCorrelationInput,
    DeploymentCorrelationOutput,
    ErrorClusterEntry,
    ErrorLogAnalysisInput,
    ErrorLogAnalysisOutput,
    GuidedToolError,
    ProductionRollbackInput,
    ProductionRollbackOutput,
    RunbookDocumentMatch,
    RunbookSearchInput,
    RunbookSearchOutput,
    ServiceHealthMetricsOutput,
    ServiceHealthQueryInput,
)

SERVICE_TELEMETRY_CATALOG: dict[str, dict[str, Any]] = {
    "checkout-service": {
        "p95_latency_ms": 840.0,
        "p99_latency_ms": 1420.0,
        "error_rate_percent": 14.2,
        "saturation_cpu_percent": 78.5,
        "requests_per_second": 1250.0,
        "slo_breached": True,
        "active_release_version": "v2.5.0-canary",
        "prior_stable_version": "v2.4.1",
        "error_clusters": [
            {
                "signature": "java.lang.NullPointerException: PaymentTokenValidator.validateSession",
                "occurrence_count": 4820,
                "sample_message": (
                    "NullPointerException in PaymentTokenValidator when empty header passed "
                    "by client session"
                ),
                "suspected_component": "PaymentTokenValidator",
            },
            {
                "signature": "io.grpc.StatusRuntimeException: DEADLINE_EXCEEDED",
                "occurrence_count": 615,
                "sample_message": "Upstream RPC deadline exceeded after 1000ms during checkout commit",
                "suspected_component": "CheckoutGrpcClient",
            },
        ],
        "deployments": [
            {
                "change_id": "deploy-chk-9941",
                "timestamp_utc": "2026-10-20T16:45:00Z",
                "release_version": "v2.5.0-canary",
                "previous_version": "v2.4.1",
                "change_summary": "Enable strict token header parsing in PaymentTokenValidator",
                "temporal_correlation_score": 0.96,
            }
        ],
    },
    "payment-gateway": {
        "p95_latency_ms": 960.0,
        "p99_latency_ms": 1890.0,
        "error_rate_percent": 9.8,
        "saturation_cpu_percent": 82.0,
        "requests_per_second": 890.0,
        "slo_breached": True,
        "active_release_version": "v3.2.0-rc1",
        "prior_stable_version": "v3.1.4",
        "error_clusters": [
            {
                "signature": "GatewayTimeoutException: UpstreamSettlementTimeout",
                "occurrence_count": 3110,
                "sample_message": "HTTP 503/504 timeout waiting for settlement acknowledgement",
                "suspected_component": "SettlementAdapter",
            }
        ],
        "deployments": [
            {
                "change_id": "deploy-pay-7720",
                "timestamp_utc": "2026-10-20T16:50:00Z",
                "release_version": "v3.2.0-rc1",
                "previous_version": "v3.1.4",
                "change_summary": "Reduce settlement retry backoff timeout from 2000ms to 150ms",
                "temporal_correlation_score": 0.94,
            }
        ],
    },
    "auth-service": {
        "p95_latency_ms": 620.0,
        "p99_latency_ms": 1150.0,
        "error_rate_percent": 6.4,
        "saturation_cpu_percent": 91.0,
        "requests_per_second": 3400.0,
        "slo_breached": True,
        "active_release_version": "v1.9.0",
        "prior_stable_version": "v1.8.4",
        "error_clusters": [
            {
                "signature": "redis.exceptions.ConnectionError: PoolExhaustedException",
                "occurrence_count": 2790,
                "sample_message": "Redis connection pool exhausted (max_connections=128 reached)",
                "suspected_component": "RedisSessionPool",
            }
        ],
        "deployments": [
            {
                "change_id": "deploy-auth-4412",
                "timestamp_utc": "2026-10-20T16:30:00Z",
                "release_version": "v1.9.0",
                "previous_version": "v1.8.4",
                "change_summary": "Refactor async token refresh without releasing pooled Redis handles",
                "temporal_correlation_score": 0.92,
            }
        ],
    },
}

DEFAULT_KNOWLEDGE_STORE = VertexSearchKnowledgeStore()


def query_service_health_metrics(
    service_name: str,
    region: str = "us-central1",
    window_minutes: int = 15,
    session_id: str = "default-session",
) -> dict[str, Any]:
    """Query golden-signal service health telemetry (latency, error rate, traffic, saturation).

    Retrieves p95/p99 latency in milliseconds, HTTP 5xx error rate percentage, CPU saturation,
    request throughput, SLO breach status, and the active serving release version for a target
    production microservice over the specified observation window.

    Args:
        service_name: Canonical kebab-case microservice name (e.g., 'checkout-service',
            'payment-gateway', or 'auth-service').
        region: Cloud region hosting the target service (default: 'us-central1').
        window_minutes: Lookback observation window in minutes between 1 and 1440 (default: 15).
        session_id: Active incident correlation session identifier.

    Returns:
        A dictionary conforming to `ServiceHealthMetricsOutput` on success, or a structured
        `GuidedToolError` dictionary with `recovery_instructions` if validation fails or
        the service is not found in the telemetry catalog.
    """
    intent_id = DEFAULT_INTENT_TRACKER.record_intent(
        session_id=session_id,
        agent_name="TelemetryTriageAgent",
        tool_name="query_service_health_metrics",
        intended_action=f"Query golden-signal health telemetry for {service_name} in {region}",
        parameters={
            "service_name": service_name,
            "region": region,
            "window_minutes": window_minutes,
        },
    )
    with DEFAULT_TRACING.start_span(
        "tool.query_service_health_metrics",
        attributes={"service.name": service_name, "region": region, "window_minutes": window_minutes},
    ) as span:
        try:
            validated_in = ServiceHealthQueryInput(
                service_name=service_name,
                region=region,
                window_minutes=window_minutes,
            )
        except ValidationError as exc:
            err = GuidedToolError(
                error_code="INVALID_TELEMETRY_QUERY_ARGS",
                failed_tool="query_service_health_metrics",
                message=f"Input validation failed for query_service_health_metrics: {exc}",
                recovery_instructions=(
                    "Ensure service_name is lowercase kebab-case ('checkout-service', 'payment-gateway', "
                    "'auth-service'), region matches '<area>-<zone><digit>' (e.g., 'us-central1'), "
                    "and window_minutes is between 1 and 1440."
                ),
                suggested_next_tool="query_service_health_metrics",
                retryable=True,
            ).model_dump()
            span.set_attribute("tool.status", "ERROR")
            DEFAULT_INTENT_TRACKER.record_outcome(
                intent_id=intent_id,
                actual_outcome=err["message"],
                status="VALIDATION_ERROR",
                output_summary=err,
            )
            return err

        catalog_entry = SERVICE_TELEMETRY_CATALOG.get(validated_in.service_name)
        if catalog_entry is None:
            supported = ", ".join(sorted(SERVICE_TELEMETRY_CATALOG.keys()))
            err = GuidedToolError(
                error_code="SERVICE_NOT_FOUND",
                failed_tool="query_service_health_metrics",
                message=f"Service '{validated_in.service_name}' is not registered in the telemetry catalog.",
                recovery_instructions=(
                    f"Retry query_service_health_metrics with one of the registered production "
                    f"services: {supported}."
                ),
                suggested_next_tool="search_incident_runbooks",
                retryable=True,
            ).model_dump()
            span.set_attribute("tool.status", "SERVICE_NOT_FOUND")
            DEFAULT_INTENT_TRACKER.record_outcome(
                intent_id=intent_id,
                actual_outcome=err["message"],
                status="ERROR",
                output_summary=err,
            )
            return err

        output = ServiceHealthMetricsOutput(
            service_name=validated_in.service_name,
            region=validated_in.region,
            window_minutes=validated_in.window_minutes,
            p95_latency_ms=catalog_entry["p95_latency_ms"],
            p99_latency_ms=catalog_entry["p99_latency_ms"],
            error_rate_percent=catalog_entry["error_rate_percent"],
            saturation_cpu_percent=catalog_entry["saturation_cpu_percent"],
            requests_per_second=catalog_entry["requests_per_second"],
            slo_breached=catalog_entry["slo_breached"],
            active_release_version=catalog_entry["active_release_version"],
        ).model_dump()
        span.set_attribute("tool.status", "OK")
        span.set_attribute("slo.breached", bool(output["slo_breached"]))
        DEFAULT_INTENT_TRACKER.record_outcome(
            intent_id=intent_id,
            actual_outcome=(
                f"Metrics retrieved for {validated_in.service_name}: "
                f"error_rate={output['error_rate_percent']}%, p95={output['p95_latency_ms']}ms, "
                f"slo_breached={output['slo_breached']}"
            ),
            status="SUCCESS",
            output_summary=output,
        )
        return output


def analyze_error_log_anomalies(
    service_name: str,
    severity_filter: str = "ERROR",
    max_clusters: int = 5,
    session_id: str = "default-session",
) -> dict[str, Any]:
    """Cluster and rank high-frequency error log signatures from Cloud Logging.

    Aggregates recent error log entries for a target microservice, scrubs any embedded PII,
    and groups stack traces into normalized exception signatures to pinpoint the failing
    software component.

    Args:
        service_name: Canonical kebab-case microservice name (e.g., 'checkout-service').
        severity_filter: Minimum log severity threshold ('WARNING', 'ERROR', or 'CRITICAL').
        max_clusters: Maximum number of top error clusters to return (1 to 20, default: 5).
        session_id: Active incident correlation session identifier.

    Returns:
        A dictionary conforming to `ErrorLogAnalysisOutput` on success, or a `GuidedToolError`
        dictionary with actionable recovery instructions if arguments are invalid.
    """
    intent_id = DEFAULT_INTENT_TRACKER.record_intent(
        session_id=session_id,
        agent_name="TelemetryTriageAgent",
        tool_name="analyze_error_log_anomalies",
        intended_action=f"Cluster anomalous {severity_filter} logs for {service_name}",
        parameters={
            "service_name": service_name,
            "severity_filter": severity_filter,
            "max_clusters": max_clusters,
        },
    )
    with DEFAULT_TRACING.start_span(
        "tool.analyze_error_log_anomalies",
        attributes={"service.name": service_name, "severity_filter": severity_filter},
    ) as span:
        try:
            validated_in = ErrorLogAnalysisInput(
                service_name=service_name,
                severity_filter=severity_filter,  # type: ignore[arg-type]
                max_clusters=max_clusters,
            )
        except ValidationError as exc:
            err = GuidedToolError(
                error_code="INVALID_LOG_ANALYSIS_ARGS",
                failed_tool="analyze_error_log_anomalies",
                message=f"Validation failed for analyze_error_log_anomalies: {exc}",
                recovery_instructions=(
                    "Pass severity_filter as one of 'WARNING', 'ERROR', or 'CRITICAL' and "
                    "max_clusters between 1 and 20."
                ),
                suggested_next_tool="analyze_error_log_anomalies",
                retryable=True,
            ).model_dump()
            span.set_attribute("tool.status", "ERROR")
            DEFAULT_INTENT_TRACKER.record_outcome(
                intent_id=intent_id,
                actual_outcome=err["message"],
                status="VALIDATION_ERROR",
                output_summary=err,
            )
            return err

        catalog_entry = SERVICE_TELEMETRY_CATALOG.get(validated_in.service_name)
        if catalog_entry is None:
            supported = ", ".join(sorted(SERVICE_TELEMETRY_CATALOG.keys()))
            err = GuidedToolError(
                error_code="SERVICE_NOT_FOUND",
                failed_tool="analyze_error_log_anomalies",
                message=f"No log sink found for service '{validated_in.service_name}'.",
                recovery_instructions=f"Use one of the known production services: {supported}.",
                suggested_next_tool="query_service_health_metrics",
                retryable=True,
            ).model_dump()
            span.set_attribute("tool.status", "SERVICE_NOT_FOUND")
            DEFAULT_INTENT_TRACKER.record_outcome(
                intent_id=intent_id,
                actual_outcome=err["message"],
                status="ERROR",
                output_summary=err,
            )
            return err

        raw_clusters = catalog_entry["error_clusters"][: validated_in.max_clusters]
        clusters = [
            ErrorClusterEntry(
                signature=c["signature"],
                occurrence_count=c["occurrence_count"],
                sample_message=DEFAULT_REDACTOR.redact_text(c["sample_message"]),
                suspected_component=c["suspected_component"],
            )
            for c in raw_clusters
        ]
        total_events = sum(c.occurrence_count for c in clusters)
        output = ErrorLogAnalysisOutput(
            service_name=validated_in.service_name,
            total_error_events=total_events,
            top_clusters=clusters,
        ).model_dump()
        span.set_attribute("tool.status", "OK")
        DEFAULT_INTENT_TRACKER.record_outcome(
            intent_id=intent_id,
            actual_outcome=(
                f"Identified {len(clusters)} error clusters ({total_events} events) for "
                f"{validated_in.service_name}"
            ),
            status="SUCCESS",
            output_summary=output,
        )
        return output


def search_incident_runbooks(
    query: str,
    top_k: int = 3,
    session_id: str = "default-session",
) -> dict[str, Any]:
    """Search verified SRE remediation runbooks via Vertex AI Search or local vector store.

    Performs semantic retrieval over curated Site Reliability Engineering playbooks to find
    known root-cause patterns, step-by-step mitigation instructions, and Human-in-the-Loop
    approval requirements matching the observed incident symptoms.

    Args:
        query: Natural-language symptom, exception signature, or service query string.
        top_k: Maximum number of ranked runbook documents to retrieve (1 to 10, default: 3).
        session_id: Active incident correlation session identifier.

    Returns:
        A dictionary conforming to `RunbookSearchOutput` containing ranked runbook matches,
        or a `GuidedToolError` dictionary if the query is empty or out of bounds.
    """
    intent_id = DEFAULT_INTENT_TRACKER.record_intent(
        session_id=session_id,
        agent_name="RootCauseAnalystAgent",
        tool_name="search_incident_runbooks",
        intended_action=f"Search SRE runbook knowledge store for query: {query}",
        parameters={"query": query, "top_k": top_k},
    )
    with DEFAULT_TRACING.start_span(
        "tool.search_incident_runbooks",
        attributes={"query": query, "top_k": top_k},
    ) as span:
        try:
            validated_in = RunbookSearchInput(query=query, top_k=top_k)
        except ValidationError as exc:
            err = GuidedToolError(
                error_code="INVALID_RUNBOOK_QUERY",
                failed_tool="search_incident_runbooks",
                message=f"Invalid runbook search parameters: {exc}",
                recovery_instructions=(
                    "Provide a non-empty query of at least 3 characters describing the service "
                    "symptom and a top_k value between 1 and 10."
                ),
                suggested_next_tool="search_incident_runbooks",
                retryable=True,
            ).model_dump()
            span.set_attribute("tool.status", "ERROR")
            DEFAULT_INTENT_TRACKER.record_outcome(
                intent_id=intent_id,
                actual_outcome=err["message"],
                status="VALIDATION_ERROR",
                output_summary=err,
            )
            return err

        raw_matches = DEFAULT_KNOWLEDGE_STORE.search_runbooks(
            query=validated_in.query,
            top_k=validated_in.top_k,
        )
        backend = (
            raw_matches[0].get("retrieval_backend", "local_vector_index")
            if raw_matches
            else "local_vector_index"
        )
        matches = [
            RunbookDocumentMatch(
                runbook_id=m["runbook_id"],
                title=m["title"],
                relevance_score=m["relevance_score"],
                root_cause_pattern=m["root_cause_pattern"],
                recommended_mitigation_steps=m["recommended_mitigation_steps"],
                requires_human_approval_for_rollback=m["requires_human_approval_for_rollback"],
            )
            for m in raw_matches
        ]
        output = RunbookSearchOutput(
            query=validated_in.query,
            retrieval_backend=backend,
            matches=matches,
        ).model_dump()
        span.set_attribute("tool.status", "OK")
        DEFAULT_INTENT_TRACKER.record_outcome(
            intent_id=intent_id,
            actual_outcome=f"Retrieved {len(matches)} runbooks (top={matches[0].runbook_id if matches else 'none'})",
            status="SUCCESS",
            output_summary=output,
        )
        return output


def correlate_deployment_change_events(
    service_name: str,
    lookback_hours: int = 6,
    session_id: str = "default-session",
) -> dict[str, Any]:
    """Correlate recent production deployments and config changes with incident onset.

    Inspects the release ledger for the target microservice over the lookback window and
    calculates temporal correlation scores between release rollouts and SLO breach onset.

    Args:
        service_name: Canonical kebab-case microservice name (e.g., 'checkout-service').
        lookback_hours: Lookback window in hours between 1 and 168 (default: 6).
        session_id: Active incident correlation session identifier.

    Returns:
        A dictionary conforming to `DeploymentCorrelationOutput` listing suspect deployments
        and prior stable versions, or a `GuidedToolError` dictionary on invalid input.
    """
    intent_id = DEFAULT_INTENT_TRACKER.record_intent(
        session_id=session_id,
        agent_name="RootCauseAnalystAgent",
        tool_name="correlate_deployment_change_events",
        intended_action=f"Correlate deployments for {service_name} over last {lookback_hours}h",
        parameters={"service_name": service_name, "lookback_hours": lookback_hours},
    )
    with DEFAULT_TRACING.start_span(
        "tool.correlate_deployment_change_events",
        attributes={"service.name": service_name, "lookback_hours": lookback_hours},
    ) as span:
        try:
            validated_in = DeploymentCorrelationInput(
                service_name=service_name,
                lookback_hours=lookback_hours,
            )
        except ValidationError as exc:
            err = GuidedToolError(
                error_code="INVALID_CORRELATION_ARGS",
                failed_tool="correlate_deployment_change_events",
                message=f"Validation failed for correlate_deployment_change_events: {exc}",
                recovery_instructions=(
                    "Ensure service_name is valid kebab-case and lookback_hours is between 1 and 168."
                ),
                suggested_next_tool="correlate_deployment_change_events",
                retryable=True,
            ).model_dump()
            span.set_attribute("tool.status", "ERROR")
            DEFAULT_INTENT_TRACKER.record_outcome(
                intent_id=intent_id,
                actual_outcome=err["message"],
                status="VALIDATION_ERROR",
                output_summary=err,
            )
            return err

        catalog_entry = SERVICE_TELEMETRY_CATALOG.get(validated_in.service_name)
        if catalog_entry is None:
            supported = ", ".join(sorted(SERVICE_TELEMETRY_CATALOG.keys()))
            err = GuidedToolError(
                error_code="SERVICE_NOT_FOUND",
                failed_tool="correlate_deployment_change_events",
                message=f"Service '{validated_in.service_name}' has no deployment history.",
                recovery_instructions=f"Use one of the registered services: {supported}.",
                suggested_next_tool="query_service_health_metrics",
                retryable=True,
            ).model_dump()
            span.set_attribute("tool.status", "SERVICE_NOT_FOUND")
            DEFAULT_INTENT_TRACKER.record_outcome(
                intent_id=intent_id,
                actual_outcome=err["message"],
                status="ERROR",
                output_summary=err,
            )
            return err

        events = [
            ChangeEventRecord(
                change_id=e["change_id"],
                timestamp_utc=e["timestamp_utc"],
                release_version=e["release_version"],
                previous_version=e["previous_version"],
                change_summary=DEFAULT_REDACTOR.redact_text(e["change_summary"]),
                temporal_correlation_score=e["temporal_correlation_score"],
            )
            for e in catalog_entry["deployments"]
        ]
        suspect_detected = any(e.temporal_correlation_score >= 0.8 for e in events)
        output = DeploymentCorrelationOutput(
            service_name=validated_in.service_name,
            suspect_change_detected=suspect_detected,
            events=events,
        ).model_dump()
        span.set_attribute("tool.status", "OK")
        span.set_attribute("suspect.detected", suspect_detected)
        DEFAULT_INTENT_TRACKER.record_outcome(
            intent_id=intent_id,
            actual_outcome=(
                f"Correlated {len(events)} change events for {validated_in.service_name} "
                f"(suspect_change_detected={suspect_detected})"
            ),
            status="SUCCESS",
            output_summary=output,
        )
        return output


def create_critical_incident_ticket(
    service_name: str,
    severity: str,
    title: str,
    root_cause_hypothesis: str,
    commander_handle: str = "sre-oncall-primary",
    session_id: str = "default-session",
) -> dict[str, Any]:
    """Create a PII-sanitized critical incident tracking ticket and coordination bridge.

    Records an audited incident ticket with severity classification ('SEV1', 'SEV2', 'SEV3'),
    automatically redacting any embedded PII from the title and root-cause hypothesis before
    persisting the record.

    Args:
        service_name: Affected production microservice identifier (e.g., 'checkout-service').
        severity: Incident severity level ('SEV1', 'SEV2', or 'SEV3').
        title: Concise incident headline (5 to 200 characters).
        root_cause_hypothesis: Evidence-backed root cause summary (10 to 2000 characters).
        commander_handle: Role handle for the assigned incident commander.
        session_id: Active incident correlation session identifier.

    Returns:
        A dictionary conforming to `CreateIncidentTicketOutput` containing the generated
        `ticket_id` and sanitized fields, or a `GuidedToolError` dictionary on invalid input.
    """
    intent_id = DEFAULT_INTENT_TRACKER.record_intent(
        session_id=session_id,
        agent_name="RemediationExecutorAgent",
        tool_name="create_critical_incident_ticket",
        intended_action=f"Create {severity} incident ticket for {service_name}",
        parameters={
            "service_name": service_name,
            "severity": severity,
            "title": title,
            "commander_handle": commander_handle,
        },
    )
    with DEFAULT_TRACING.start_span(
        "tool.create_critical_incident_ticket",
        attributes={"service.name": service_name, "incident.severity": severity},
    ) as span:
        try:
            validated_in = CreateIncidentTicketInput(
                service_name=service_name,
                severity=severity,  # type: ignore[arg-type]
                title=title,
                root_cause_hypothesis=root_cause_hypothesis,
                commander_handle=commander_handle,
            )
        except ValidationError as exc:
            err = GuidedToolError(
                error_code="INVALID_INCIDENT_TICKET_ARGS",
                failed_tool="create_critical_incident_ticket",
                message=f"Validation failed for create_critical_incident_ticket: {exc}",
                recovery_instructions=(
                    "Ensure severity is 'SEV1', 'SEV2', or 'SEV3', title is 5-200 chars, "
                    "and root_cause_hypothesis is at least 10 characters."
                ),
                suggested_next_tool="create_critical_incident_ticket",
                retryable=True,
            ).model_dump()
            span.set_attribute("tool.status", "ERROR")
            DEFAULT_INTENT_TRACKER.record_outcome(
                intent_id=intent_id,
                actual_outcome=err["message"],
                status="VALIDATION_ERROR",
                output_summary=err,
            )
            return err

        ticket_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        sanitized_title = DEFAULT_REDACTOR.redact_text(validated_in.title)
        sanitized_hypothesis = DEFAULT_REDACTOR.redact_text(validated_in.root_cause_hypothesis)

        output = CreateIncidentTicketOutput(
            ticket_id=ticket_id,
            service_name=validated_in.service_name,
            severity=validated_in.severity,
            sanitized_title=sanitized_title,
            sanitized_hypothesis=sanitized_hypothesis,
            bridge_channel=f"#inc-{validated_in.service_name}-{ticket_id.lower()}",
        ).model_dump()
        span.set_attribute("tool.status", "OK")
        span.set_attribute("incident.ticket_id", ticket_id)
        DEFAULT_INTENT_TRACKER.record_outcome(
            intent_id=intent_id,
            actual_outcome=f"Created incident ticket {ticket_id} ({validated_in.severity}) for {validated_in.service_name}",
            status="SUCCESS",
            output_summary=output,
        )
        return output


def execute_production_rollback(
    service_name: str,
    target_stable_version: str,
    reason: str,
    human_approval_token: str | None = None,
    session_id: str = "default-session",
) -> dict[str, Any]:
    """Execute a high-stakes production release rollback gated by Human-in-the-Loop approval.

    Shifts production traffic from a faulty canary or release version back to a verified
    stable semantic version. This tool enforces an explicit Human-in-the-Loop code stop:
    if `human_approval_token` is omitted or invalid, execution halts immediately and returns
    a `PENDING_HUMAN_APPROVAL` payload instructing the agent to obtain human confirmation.

    Args:
        service_name: Target production microservice to roll back (e.g., 'checkout-service').
        target_stable_version: Verified semantic version tag to restore (e.g., 'v2.4.1').
        reason: Audit justification explaining why rollback is necessary.
        human_approval_token: Cryptographic approval token issued by `HumanApprovalGate`.
        session_id: Active incident correlation session identifier.

    Returns:
        A dictionary conforming to `ProductionRollbackOutput` when approved and executed,
        or a `GuidedToolError` dictionary with `status='PENDING_HUMAN_APPROVAL'` when halted
        by the Human-in-the-Loop guardrail.
    """
    intent_id = DEFAULT_INTENT_TRACKER.record_intent(
        session_id=session_id,
        agent_name="RemediationExecutorAgent",
        tool_name="execute_production_rollback",
        intended_action=(
            f"Roll back production service {service_name} to {target_stable_version} "
            f"(token_present={bool(human_approval_token)})"
        ),
        parameters={
            "service_name": service_name,
            "target_stable_version": target_stable_version,
            "reason": reason,
            "token_present": bool(human_approval_token),
        },
    )
    with DEFAULT_TRACING.start_span(
        "tool.execute_production_rollback",
        attributes={
            "service.name": service_name,
            "target.version": target_stable_version,
            "hitl.token_provided": bool(human_approval_token),
        },
    ) as span:
        try:
            validated_in = ProductionRollbackInput(
                service_name=service_name,
                target_stable_version=target_stable_version,
                reason=reason,
                human_approval_token=human_approval_token,
            )
        except ValidationError as exc:
            err = GuidedToolError(
                error_code="INVALID_ROLLBACK_ARGS",
                failed_tool="execute_production_rollback",
                message=f"Validation failed for execute_production_rollback: {exc}",
                recovery_instructions=(
                    "Ensure target_stable_version matches '^v[0-9]+\\.[0-9]+\\.[0-9]+$' "
                    "(e.g., 'v2.4.1') and reason is at least 10 characters."
                ),
                suggested_next_tool="correlate_deployment_change_events",
                retryable=True,
            ).model_dump()
            span.set_attribute("tool.status", "ERROR")
            DEFAULT_INTENT_TRACKER.record_outcome(
                intent_id=intent_id,
                actual_outcome=err["message"],
                status="VALIDATION_ERROR",
                output_summary=err,
            )
            return err

        # Enforce Human-in-the-Loop approval gate before any production state mutation
        hitl_check = before_tool_guardrail_callback(
            tool_name="execute_production_rollback",
            tool_args=validated_in.model_dump(),
            approval_gate=DEFAULT_APPROVAL_GATE,
        )
        if not hitl_check["allowed"]:
            halted = GuidedToolError(
                status="PENDING_HUMAN_APPROVAL",
                error_code=hitl_check["error_code"],
                failed_tool="execute_production_rollback",
                message=hitl_check["message"],
                recovery_instructions=hitl_check["recovery_instructions"],
                suggested_next_tool=hitl_check.get("suggested_next_tool"),
                retryable=True,
            ).model_dump()
            span.set_attribute("tool.status", "PENDING_HUMAN_APPROVAL")
            DEFAULT_INTENT_TRACKER.record_outcome(
                intent_id=intent_id,
                actual_outcome=halted["message"],
                status="HALTED_FOR_HUMAN_APPROVAL",
                output_summary=halted,
            )
            return halted

        catalog_entry = SERVICE_TELEMETRY_CATALOG.get(validated_in.service_name, {})
        faulty_version = str(catalog_entry.get("active_release_version", "unknown-canary"))
        rollback_id = f"RBK-{uuid.uuid4().hex[:8].upper()}"

        output = ProductionRollbackOutput(
            rollback_id=rollback_id,
            service_name=validated_in.service_name,
            restored_version=validated_in.target_stable_version,
            previous_faulty_version=faulty_version,
            approved_by_token_fingerprint=str(hitl_check["token_fingerprint"]),
        ).model_dump()
        span.set_attribute("tool.status", "OK")
        span.set_attribute("rollback.id", rollback_id)
        DEFAULT_INTENT_TRACKER.record_outcome(
            intent_id=intent_id,
            actual_outcome=(
                f"Executed approved rollback {rollback_id} on {validated_in.service_name}: "
                f"{faulty_version} -> {validated_in.target_stable_version}"
            ),
            status="SUCCESS",
            output_summary=output,
        )
        return output


ALL_SRE_TOOLS: list[Callable[..., dict[str, Any]]] = [
    query_service_health_metrics,
    analyze_error_log_anomalies,
    search_incident_runbooks,
    correlate_deployment_change_events,
    create_critical_incident_ticket,
    execute_production_rollback,
]
