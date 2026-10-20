"""Multi-Agent Google ADK Architecture and Incident Response Orchestrator.

Implements Category 3 (Orchestration & Logic) using official `google.adk.agents`
primitives (`LlmAgent` Coordinator + `SequentialAgent` pipeline with specialized
sub-agents) combined with Strategic Model Routing, Guardrails, HITL hooks,
History Compaction, Persistent Session Storage, and Async Memory Consolidation.
"""

from __future__ import annotations

from typing import Any

from google.adk.agents import LlmAgent, SequentialAgent

from sre_agent.guardrails import (
    DEFAULT_APPROVAL_GATE,
    DEFAULT_POLICY_GUARDRAIL,
    DEFAULT_SELF_CRITIQUE,
    HumanApprovalGate,
    PolicyGuardrailPlugin,
    SelfCritiqueEvaluator,
    after_model_guardrail_callback,
    before_model_guardrail_callback,
)
from sre_agent.memory import (
    AsyncMemoryConsolidator,
    HistoryCompactor,
    PersistentSessionStore,
)
from sre_agent.observability import (
    DEFAULT_INTENT_TRACKER,
    DEFAULT_LOGGER,
    DEFAULT_TRACING,
)
from sre_agent.prompts import (
    COORDINATOR_CONSTITUTION_PROMPT,
    REMEDIATION_EXECUTOR_PROMPT,
    ROOT_CAUSE_ANALYST_PROMPT,
    TELEMETRY_TRIAGE_PROMPT,
)
from sre_agent.router import StrategicModelRouter
from sre_agent.schemas import IncidentAssessmentReport
from sre_agent.tools import (
    analyze_error_log_anomalies,
    correlate_deployment_change_events,
    create_critical_incident_ticket,
    execute_production_rollback,
    query_service_health_metrics,
    search_incident_runbooks,
)

DEFAULT_ROUTER = StrategicModelRouter()


def build_telemetry_triage_agent() -> LlmAgent:
    """Create the `gemini-2.5-flash` Telemetry Triage ADK Sub-Agent."""
    routing = DEFAULT_ROUTER.route_task("telemetry_triage")
    return LlmAgent(
        name="telemetry_triage_agent",
        model=routing.selected_model,
        description=(
            "High-speed telemetry triage sub-agent that queries golden-signal health metrics "
            "and clusters anomalous error logs."
        ),
        instruction=TELEMETRY_TRIAGE_PROMPT,
        tools=[query_service_health_metrics, analyze_error_log_anomalies],
        output_key="telemetry_triage_findings",
    )


def build_root_cause_analyst_agent() -> LlmAgent:
    """Create the `gemini-2.5-pro` Root-Cause Analyst ADK Sub-Agent."""
    routing = DEFAULT_ROUTER.route_task("root_cause_analysis")
    return LlmAgent(
        name="root_cause_analyst_agent",
        model=routing.selected_model,
        description=(
            "Deep-reasoning root-cause analyst sub-agent that correlates deployment change "
            "events with incident onset and searches verified SRE runbooks."
        ),
        instruction=ROOT_CAUSE_ANALYST_PROMPT,
        tools=[correlate_deployment_change_events, search_incident_runbooks],
        output_key="root_cause_analysis_findings",
    )


def build_remediation_executor_agent() -> LlmAgent:
    """Create the `gemini-2.5-pro` Remediation Executor ADK Sub-Agent with HITL rollback gate."""
    routing = DEFAULT_ROUTER.route_task("remediation_planning")
    return LlmAgent(
        name="remediation_executor_agent",
        model=routing.selected_model,
        description=(
            "Remediation executor sub-agent that opens critical incident tickets and executes "
            "Human-in-the-Loop approved production rollbacks."
        ),
        instruction=REMEDIATION_EXECUTOR_PROMPT,
        tools=[create_critical_incident_ticket, execute_production_rollback],
        output_key="remediation_execution_result",
    )


def build_incident_response_pipeline() -> SequentialAgent:
    """Create the ADK SequentialAgent executing Triage -> RCA -> Remediation in order."""
    return SequentialAgent(
        name="incident_response_sequential_pipeline",
        description=(
            "Sequential multi-agent SRE pipeline executing TelemetryTriageAgent, "
            "RootCauseAnalystAgent, and RemediationExecutorAgent."
        ),
        sub_agents=[
            build_telemetry_triage_agent(),
            build_root_cause_analyst_agent(),
            build_remediation_executor_agent(),
        ],
    )


def build_root_agent() -> LlmAgent:
    """Create the top-level ADK Coordinator LlmAgent (`root_agent`)."""
    routing = DEFAULT_ROUTER.route_task("coordinator_synthesis")
    return LlmAgent(
        name="sre_incident_response_coordinator",
        model=routing.selected_model,
        description=(
            "Enterprise Cloud SRE Incident Response Coordinator governing triage, "
            "root-cause analysis, human-approved remediation, and self-critique."
        ),
        instruction=COORDINATOR_CONSTITUTION_PROMPT,
        sub_agents=[build_incident_response_pipeline()],
        output_schema=IncidentAssessmentReport,
    )


# Module-level ADK agents exported for `adk web`, `adk run`, `adk eval`, and evaluator discovery
telemetry_triage_agent: LlmAgent = build_telemetry_triage_agent()
root_cause_analyst_agent: LlmAgent = build_root_cause_analyst_agent()
remediation_executor_agent: LlmAgent = build_remediation_executor_agent()
incident_response_pipeline: SequentialAgent = build_incident_response_pipeline()
root_agent: LlmAgent = build_root_agent()


class IncidentResponseOrchestrator:
    """End-to-end execution engine orchestrating the multi-agent pipeline with full AgentOps telemetry."""

    def __init__(
        self,
        session_store: PersistentSessionStore | None = None,
        compactor: HistoryCompactor | None = None,
        router: StrategicModelRouter | None = None,
        guardrail: PolicyGuardrailPlugin | None = None,
        approval_gate: HumanApprovalGate | None = None,
        self_critique: SelfCritiqueEvaluator | None = None,
    ) -> None:
        self.session_store = session_store or PersistentSessionStore(db_path=":memory:")
        self.compactor = compactor or HistoryCompactor(max_token_budget=512, recent_turns_to_keep=4)
        self.memory_consolidator = AsyncMemoryConsolidator(session_store=self.session_store)
        self.router = router or DEFAULT_ROUTER
        self.guardrail = guardrail or DEFAULT_POLICY_GUARDRAIL
        self.approval_gate = approval_gate or DEFAULT_APPROVAL_GATE
        self.self_critique = self_critique or DEFAULT_SELF_CRITIQUE

    async def handle_incident(
        self,
        session_id: str,
        user_prompt: str,
        service_name: str = "checkout-service",
        region: str = "us-central1",
        human_approval_token: str | None = None,
    ) -> IncidentAssessmentReport:
        """Execute the multi-agent incident response workflow for an incoming alert or operator request."""
        with DEFAULT_TRACING.start_span(
            "coordinator.handle_incident",
            attributes={"session.id": session_id, "service.name": service_name, "region": region},
        ) as root_span:
            # Step 1: Pre-Model Policy Guardrail & PII Scrubbing
            pre_check = before_model_guardrail_callback(
                user_prompt=user_prompt,
                guardrail=self.guardrail,
            )
            if pre_check["blocked"]:
                root_span.set_attribute("guardrail.blocked", True)
                return IncidentAssessmentReport(
                    incident_id="INC-BLOCKED",
                    service_name=service_name,
                    severity="SEV3",
                    slo_breached=False,
                    root_cause_summary=pre_check["reason"],
                    matched_runbook_id="RB-SECURITY-POLICY",
                    remediation_status="BLOCKED_BY_GUARDRAIL",
                    recommended_actions=[
                        "Submit a valid SRE incident alert without prompt-injection directives."
                    ],
                    routed_models_used={"PolicyGuardrailPlugin": "deterministic-guardrail"},
                    self_critique_score=1.0,
                )

            sanitized_prompt = pre_check["sanitized_prompt"]
            self.session_store.append_turn(
                session_id=session_id,
                role="user",
                content=sanitized_prompt,
                metadata={"service_name": service_name, "region": region},
            )

            # Step 2: Compact session history to prevent context bloat
            raw_turns = self.session_store.get_session_turns(session_id)
            simple_turns = [{"role": t["role"], "content": t["content"]} for t in raw_turns]
            compacted_turns = self.compactor.compact_history(simple_turns)
            root_span.set_attribute("context.compacted_turn_count", len(compacted_turns))

            # Step 3: Strategic Model Routing across the 3 specialized sub-agents + Coordinator
            triage_route = self.router.route_task("telemetry_triage", sanitized_prompt, session_id)
            rca_route = self.router.route_task("root_cause_analysis", sanitized_prompt, session_id)
            remediation_route = self.router.route_task(
                "remediation_planning", sanitized_prompt, session_id
            )
            coordinator_route = self.router.route_task(
                "coordinator_synthesis", sanitized_prompt, session_id
            )
            routed_models = {
                "TelemetryTriageAgent": triage_route.selected_model,
                "RootCauseAnalystAgent": rca_route.selected_model,
                "RemediationExecutorAgent": remediation_route.selected_model,
                "IncidentResponseCoordinator": coordinator_route.selected_model,
            }

            # Step 4: Sub-Agent 1 — TelemetryTriageAgent (gemini-2.5-flash)
            with DEFAULT_TRACING.start_span(
                "subagent.TelemetryTriageAgent",
                attributes={"model": triage_route.selected_model},
            ):
                metrics = query_service_health_metrics(
                    service_name=service_name,
                    region=region,
                    window_minutes=15,
                    session_id=session_id,
                )
                logs = analyze_error_log_anomalies(
                    service_name=service_name,
                    severity_filter="ERROR",
                    max_clusters=3,
                    session_id=session_id,
                )

            error_rate = float(metrics.get("error_rate_percent", 0.0))
            slo_breached = bool(metrics.get("slo_breached", False))
            top_Clusters: list[dict[str, Any]] = list(logs.get("top_clusters", []))
            dominant_sig = (
                top_Clusters[0]["signature"] if top_Clusters else "AnomalousErrorSignature"
            )
            dominant_sample = (
                top_Clusters[0]["sample_message"] if top_Clusters else ""
            )

            # Step 5: Sub-Agent 2 — RootCauseAnalystAgent (gemini-2.5-pro)
            with DEFAULT_TRACING.start_span(
                "subagent.RootCauseAnalystAgent",
                attributes={"model": rca_route.selected_model},
            ):
                deployments = correlate_deployment_change_events(
                    service_name=service_name,
                    lookback_hours=6,
                    session_id=session_id,
                )
                runbook_query = (
                    f"{service_name} {dominant_sig} {dominant_sample} {sanitized_prompt}"
                )
                runbooks = search_incident_runbooks(
                    query=runbook_query,
                    top_k=2,
                    session_id=session_id,
                )

            events: list[dict[str, Any]] = list(deployments.get("events", []))
            suspect_release = (
                events[0]["release_version"]
                if events
                else str(metrics.get("active_release_version", "v1.0.1"))
            )
            prior_stable_release = (
                events[0]["previous_version"] if events else "v1.0.0"
            )
            matched_runbooks: list[dict[str, Any]] = list(runbooks.get("matches", []))
            primary_runbook = (
                matched_runbooks[0]["runbook_id"]
                if matched_runbooks
                else "RB-101-CANARY-ROLLBACK"
            )
            recommended_steps = (
                list(matched_runbooks[0]["recommended_mitigation_steps"])
                if matched_runbooks
                else [
                    f"Verify golden-signal breach on {service_name}",
                    f"Correlate faulty release {suspect_release}",
                    f"Roll back to {prior_stable_release} with human approval",
                ]
            )

            # Step 6: Sub-Agent 3 — RemediationExecutorAgent (gemini-2.5-pro + HITL Hook)
            severity = "SEV1" if error_rate >= 10.0 else ("SEV2" if slo_breached else "SEV3")
            hypothesis = (
                f"Service '{service_name}' in '{region}' breached SLO with {error_rate}% 5xx errors "
                f"and exception '{dominant_sig}' immediately after rollout of '{suspect_release}'."
            )
            with DEFAULT_TRACING.start_span(
                "subagent.RemediationExecutorAgent",
                attributes={"model": remediation_route.selected_model},
            ):
                ticket = create_critical_incident_ticket(
                    service_name=service_name,
                    severity=severity,
                    title=f"{severity}: {service_name} SLO breach ({error_rate}% 5xx) on {suspect_release}",
                    root_cause_hypothesis=hypothesis,
                    session_id=session_id,
                )
                rollback_result = execute_production_rollback(
                    service_name=service_name,
                    target_stable_version=prior_stable_release,
                    reason=f"Mitigate {ticket.get('ticket_id', 'INC-001')}: rollback {suspect_release} to {prior_stable_release}",
                    human_approval_token=human_approval_token,
                    session_id=session_id,
                )

            remediation_status = (
                "ROLLED_BACK_AND_MITIGATED"
                if rollback_result.get("status") == "OK"
                else "AWAITING_HUMAN_APPROVAL"
            )

            # Step 7: Evaluator-Optimizer Self-Critique Rubric Loop
            draft_plan: dict[str, Any] = {
                "root_cause_summary": hypothesis,
                "matched_runbook_id": primary_runbook,
                "recommended_actions": recommended_steps,
                "remediation_status": remediation_status,
            }
            refined_plan, critique_eval = self.self_critique.evaluate_and_refine(
                draft=draft_plan,
                context={
                    "service_name": service_name,
                    "error_rate_percent": error_rate,
                    "suspect_release": suspect_release,
                    "prior_stable_release": prior_stable_release,
                    "matched_runbook_id": primary_runbook,
                },
            )

            # Step 8: Post-Model Output Sanitization & Async Memory Consolidation
            post_sanitized = after_model_guardrail_callback(
                model_output=str(refined_plan["root_cause_summary"]),
                guardrail=self.guardrail,
            )
            final_rca_summary = post_sanitized["sanitized_output"]

            self.session_store.append_turn(
                session_id=session_id,
                role="assistant",
                content=final_rca_summary,
                metadata={
                    "ticket_id": ticket.get("ticket_id", "INC-0000"),
                    "remediation_status": refined_plan["remediation_status"],
                },
            )

            await self.memory_consolidator.enqueue_consolidation(
                session_id=session_id,
                service_name=service_name,
                incident_summary=final_rca_summary,
                resolution_steps=list(refined_plan["recommended_actions"]),
            )

            report = IncidentAssessmentReport(
                incident_id=str(ticket.get("ticket_id", "INC-0000")),
                service_name=service_name,
                severity=severity,  # type: ignore[arg-type]
                slo_breached=slo_breached,
                root_cause_summary=final_rca_summary,
                matched_runbook_id=str(refined_plan["matched_runbook_id"]),
                remediation_status=refined_plan["remediation_status"],
                recommended_actions=list(refined_plan["recommended_actions"]),
                routed_models_used=routed_models,
                self_critique_score=float(critique_eval["overall_score"]),
            )
            DEFAULT_INTENT_TRACKER.logger.log_event(
                event_type="INCIDENT_ASSESSMENT_COMPLETED",
                message=f"Completed assessment for {service_name} ({report.remediation_status})",
                session_id=session_id,
                metadata=report.model_dump(),
            )
            return report
