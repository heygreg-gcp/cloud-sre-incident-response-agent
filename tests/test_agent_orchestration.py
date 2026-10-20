"""Unit and integration tests for Constitutional Prompts, Strategic Model Routing, and ADK Multi-Agent Orchestration."""

from __future__ import annotations

import pytest
from google.adk.agents import LlmAgent, SequentialAgent

from sre_agent.agent import (
    IncidentResponseOrchestrator,
    build_incident_response_pipeline,
    build_root_agent,
    incident_response_pipeline,
    remediation_executor_agent,
    root_agent,
    root_cause_analyst_agent,
    telemetry_triage_agent,
)
from sre_agent.guardrails import DEFAULT_APPROVAL_GATE
from sre_agent.prompts import (
    COORDINATOR_CONSTITUTION_PROMPT,
    REMEDIATION_EXECUTOR_PROMPT,
    ROOT_CAUSE_ANALYST_PROMPT,
    TELEMETRY_TRIAGE_PROMPT,
)
from sre_agent.router import StrategicModelRouter


def test_constitutional_system_prompts_define_persona_domain_and_constraints() -> None:
    """Verify Category 2 criterion: Robust System Instructions with explicit Constitution."""
    for prompt in [
        COORDINATOR_CONSTITUTION_PROMPT,
        TELEMETRY_TRIAGE_PROMPT,
        ROOT_CAUSE_ANALYST_PROMPT,
        REMEDIATION_EXECUTOR_PROMPT,
    ]:
        assert "<CONSTITUTION>" in prompt
        assert "<PERSONA>" in prompt
        assert "<DOMAIN_KNOWLEDGE>" in prompt
        assert "<OPERATIONAL_CONSTRAINTS>" in prompt
        assert "<SAFETY_AND_HITL_POLICY>" in prompt


def test_strategic_model_router_assigns_flash_and_pro_appropriately() -> None:
    """Verify Category 3 criterion: Strategic Model Routing between Flash and Pro tiers."""
    router = StrategicModelRouter()

    triage_decision = router.route_task(
        task_type="telemetry_triage",
        prompt="Fetch p95 latency and 5xx rate for checkout-service",
    )
    assert triage_decision.selected_model == "gemini-2.5-flash"
    assert triage_decision.tier == "FAST_LOW_LATENCY"

    rca_decision = router.route_task(
        task_type="root_cause_analysis",
        prompt="Correlate multi-service canary deployments against NullPointerException stack traces",
    )
    assert rca_decision.selected_model == "gemini-2.5-pro"
    assert rca_decision.tier == "DEEP_REASONING"

    remediation_decision = router.route_task(
        task_type="remediation_planning",
        prompt="Synthesize SEV1 rollback plan with human approval verification",
    )
    assert remediation_decision.selected_model == "gemini-2.5-pro"


def test_adk_multi_agent_hierarchy_and_subagents_are_properly_configured() -> None:
    """Verify Category 3 criterion: Multi-Agent Patterns implemented in Google ADK."""
    assert isinstance(telemetry_triage_agent, LlmAgent)
    assert telemetry_triage_agent.model == "gemini-2.5-flash"

    assert isinstance(root_cause_analyst_agent, LlmAgent)
    assert root_cause_analyst_agent.model == "gemini-2.5-pro"

    assert isinstance(remediation_executor_agent, LlmAgent)
    assert remediation_executor_agent.model == "gemini-2.5-pro"
    assert remediation_executor_agent.before_tool_callback is not None

    assert isinstance(incident_response_pipeline, SequentialAgent)
    assert len(incident_response_pipeline.sub_agents) == 3

    assert isinstance(root_agent, LlmAgent)
    assert root_agent.name == "sre_incident_response_coordinator"
    assert len(root_agent.sub_agents) >= 1
    assert root_agent.before_model_callback is not None
    assert root_agent.after_model_callback is not None
    assert root_agent.before_tool_callback is not None

    fresh_pipeline = build_incident_response_pipeline()
    fresh_root = build_root_agent()
    assert isinstance(fresh_pipeline, SequentialAgent)
    assert isinstance(fresh_root, LlmAgent)


@pytest.mark.asyncio
async def test_orchestrator_end_to_end_incident_workflow_with_hitl_and_memory() -> None:
    """Verify end-to-end multi-agent incident orchestration, HITL gate, and async memory consolidation."""
    orchestrator = IncidentResponseOrchestrator()

    # Run 1: Without human approval token -> halts rollback at AWAITING_HUMAN_APPROVAL
    report_awaiting = await orchestrator.handle_incident(
        session_id="sess-e2e-01",
        user_prompt=(
            "URGENT: checkout-service in us-central1 is throwing HTTP 500 errors after canary rollout. "
            "Paged by operator oncall@example.com."
        ),
        service_name="checkout-service",
        region="us-central1",
        human_approval_token=None,
    )
    assert report_awaiting.service_name == "checkout-service"
    assert report_awaiting.slo_breached is True
    assert report_awaiting.matched_runbook_id == "RB-101-CANARY-ROLLBACK"
    assert report_awaiting.remediation_status == "AWAITING_HUMAN_APPROVAL"
    assert report_awaiting.routed_models_used["TelemetryTriageAgent"] == "gemini-2.5-flash"
    assert report_awaiting.routed_models_used["RootCauseAnalystAgent"] == "gemini-2.5-pro"
    assert report_awaiting.self_critique_score >= 0.85

    # Run 2: Supply human approval token -> executes rollback and transitions to ROLLED_BACK_AND_MITIGATED
    token = DEFAULT_APPROVAL_GATE.issue_approval_token(
        service_name="checkout-service",
        action="execute_production_rollback",
        target_version="v2.4.1",
    )
    report_mitigated = await orchestrator.handle_incident(
        session_id="sess-e2e-01",
        user_prompt="Approved rollback of checkout-service to v2.4.1.",
        service_name="checkout-service",
        region="us-central1",
        human_approval_token=token,
    )
    assert report_mitigated.remediation_status == "ROLLED_BACK_AND_MITIGATED"
    assert report_mitigated.self_critique_score >= 0.85
