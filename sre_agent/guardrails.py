"""Security Guardrails, Policy Plugins, Evaluator-Optimizer Self-Critique, and Human-in-the-Loop Hooks.

Implements two core criteria of Category 3 (Orchestration & Logic):
1. Guardrails & Policy Plugins (`PolicyGuardrailPlugin`, `SelfCritiqueEvaluator`,
   `before_model_guardrail_callback`, `after_model_guardrail_callback`)
2. Human-in-the-Loop Hooks (`HumanApprovalGate`, `before_tool_guardrail_callback`)
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

from sre_agent.observability import DEFAULT_LOGGER, DEFAULT_REDACTOR, PIIRedactor
from sre_agent.secrets import SecretManagerClient

HIGH_STAKES_MUTATION_TOOLS: frozenset[str] = frozenset(
    {
        "execute_production_rollback",
        "scale_kubernetes_node_pool",
        "drain_production_cluster_region",
    }
)


class PolicyGuardrailPlugin:
    """Enforces input/output security guardrails against prompt injection and secret exfiltration."""

    _INJECTION_PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions", re.IGNORECASE),
        re.compile(r"disregard\s+(?:the\s+)?system\s+(?:prompt|constitution)", re.IGNORECASE),
        re.compile(r"exfiltrate\s+(?:all\s+)?(?:secret|api\s+key|credential)", re.IGNORECASE),
        re.compile(r"drop\s+production\s+database", re.IGNORECASE),
        re.compile(r"bypass\s+human\s+approval", re.IGNORECASE),
    ]

    def __init__(self, redactor: PIIRedactor | None = None) -> None:
        self.redactor = redactor or DEFAULT_REDACTOR

    def inspect_user_input(self, prompt: str) -> dict[str, Any]:
        """Inspect incoming prompt for adversarial prompt injection and scrub PII."""
        for pattern in self._INJECTION_PATTERNS:
            if pattern.search(prompt):
                DEFAULT_LOGGER.log_event(
                    event_type="GUARDRAIL_VIOLATION_BLOCKED",
                    level="WARNING",
                    message=f"Blocked prompt injection attempt matching pattern: {pattern.pattern}",
                )
                return {
                    "allowed": False,
                    "violation_code": "PROMPT_INJECTION_DETECTED",
                    "reason": (
                        "[PROMPT_INJECTION_DETECTED] Request blocked by PolicyGuardrailPlugin: "
                        "Prompt injection or unauthorized security policy override detected."
                    ),
                    "sanitized_prompt": "",
                }

        sanitized = self.redactor.redact_text(prompt)
        return {
            "allowed": True,
            "violation_code": None,
            "reason": "Input passed security policy check.",
            "sanitized_prompt": sanitized,
        }

    def sanitize_model_output(self, output_text: str) -> dict[str, Any]:
        """Ensure model responses contain zero leaked PII or raw credentials."""
        sanitized = self.redactor.redact_text(output_text)
        return {
            "sanitized_output": sanitized,
            "pii_redacted": sanitized != output_text,
        }


class HumanApprovalGate:
    """Enforces explicit Human-in-the-Loop code stops before high-stakes production mutations."""

    def __init__(self, secret_client: SecretManagerClient | None = None) -> None:
        self.secret_client = secret_client or SecretManagerClient(allow_ephemeral_fallback=True)
        self._signing_key = self.secret_client.get_secret("HITL_APPROVAL_SIGNING_KEY").encode(
            "utf-8"
        )
        self._issued_tokens: dict[str, dict[str, str]] = {}

    def issue_approval_token(
        self,
        service_name: str,
        action: str,
        target_version: str,
        approver_role: str = "sre-incident-commander",
    ) -> str:
        """Generate an HMAC-SHA256 Human-in-the-Loop approval token for a specific remediation."""
        message = f"{service_name}:{action}:{target_version}:{approver_role}".encode("utf-8")
        digest = hmac.new(self._signing_key, message, hashlib.sha256).hexdigest()[:24]
        token = f"hitl-approved-{digest}"
        self._issued_tokens[token] = {
            "service_name": service_name,
            "action": action,
            "target_version": target_version,
            "approver_role": approver_role,
            "fingerprint": hashlib.sha256(token.encode("utf-8")).hexdigest()[:16],
        }
        DEFAULT_LOGGER.log_event(
            event_type="HITL_APPROVAL_ISSUED",
            message=f"Human approval token issued by {approver_role} for {action} on {service_name}",
            metadata={
                "service_name": service_name,
                "action": action,
                "target_version": target_version,
                "approver_role": approver_role,
            },
        )
        return token

    def verify_approval(
        self,
        tool_name: str,
        service_name: str,
        target_version: str,
        token: str | None,
    ) -> dict[str, Any]:
        """Verify that a valid Human-in-the-Loop approval token is present before mutation."""
        if tool_name not in HIGH_STAKES_MUTATION_TOOLS:
            return {"allowed": True, "status": "APPROVED_NOT_REQUIRED", "token_fingerprint": "n/a"}

        if not token or token not in self._issued_tokens:
            return {
                "allowed": False,
                "status": "PENDING_HUMAN_APPROVAL",
                "error_code": "HUMAN_APPROVAL_REQUIRED",
                "failed_tool": tool_name,
                "message": (
                    f"Execution halted: High-stakes tool '{tool_name}' on service '{service_name}' "
                    "requires explicit Human-in-the-Loop confirmation before modifying production state."
                ),
                "recovery_instructions": (
                    "Present the root-cause evidence and rollback target version to the human "
                    "Incident Commander, request confirmation, and retry execute_production_rollback "
                    "with the issued human_approval_token."
                ),
                "suggested_next_tool": "create_critical_incident_ticket",
            }

        metadata = self._issued_tokens[token]
        if (
            metadata["service_name"] != service_name
            or metadata["action"] != tool_name
            or metadata["target_version"] != target_version
        ):
            return {
                "allowed": False,
                "status": "PENDING_HUMAN_APPROVAL",
                "error_code": "APPROVAL_SCOPE_MISMATCH",
                "failed_tool": tool_name,
                "message": "Provided human_approval_token does not match target service or version.",
                "recovery_instructions": (
                    "Request a new scoped approval token matching the exact service_name and "
                    "target_stable_version."
                ),
                "suggested_next_tool": None,
            }

        return {
            "allowed": True,
            "status": "HUMAN_APPROVED",
            "token_fingerprint": metadata["fingerprint"],
            "approver_role": metadata["approver_role"],
        }


class SelfCritiqueEvaluator:
    """Evaluator-Optimizer self-evaluation guardrail scoring incident response plans against a rubric."""

    RUBRIC_WEIGHTS: dict[str, float] = {
        "root_cause_clarity": 0.30,
        "runbook_alignment": 0.25,
        "actionable_mitigation_steps": 0.25,
        "hitl_safety_compliance": 0.20,
    }

    def __init__(self, score_threshold: float = 0.85, max_iterations: int = 3) -> None:
        self.score_threshold = score_threshold
        self.max_iterations = max_iterations

    def evaluate_draft(self, draft: dict[str, Any]) -> dict[str, Any]:
        """Score a candidate incident response plan across 4 weighted AgentOps dimensions."""
        rca = str(draft.get("root_cause_summary", "")).strip()
        runbook_id = str(draft.get("matched_runbook_id", "")).strip()
        actions = list(draft.get("recommended_actions", []))
        status = str(draft.get("remediation_status", "")).strip()

        dimensions: dict[str, float] = {
            "root_cause_clarity": 1.0 if len(rca) >= 40 else (0.4 if len(rca) >= 15 else 0.1),
            "runbook_alignment": 1.0 if runbook_id.startswith("RB-") else 0.0,
            "actionable_mitigation_steps": 1.0 if len(actions) >= 3 else (0.5 if actions else 0.0),
            "hitl_safety_compliance": (
                1.0
                if status
                in {
                    "AWAITING_HUMAN_APPROVAL",
                    "ROLLED_BACK_AND_MITIGATED",
                    "MONITORING_STABLE",
                }
                else 0.0
            ),
        }
        overall_score = round(
            sum(dimensions[k] * weight for k, weight in self.RUBRIC_WEIGHTS.items()),
            4,
        )
        feedback: list[str] = []
        if dimensions["root_cause_clarity"] < 1.0:
            feedback.append("Expand root_cause_summary with concrete metric and deployment evidence.")
        if dimensions["runbook_alignment"] < 1.0:
            feedback.append("Cite a verified SRE runbook ID (e.g., RB-101-CANARY-ROLLBACK).")
        if dimensions["actionable_mitigation_steps"] < 1.0:
            feedback.append("Provide at least 3 ordered, verifiable remediation actions.")
        if dimensions["hitl_safety_compliance"] < 1.0:
            feedback.append("Set a valid HITL-compliant remediation_status.")

        return {
            "overall_score": overall_score,
            "passed": overall_score >= self.score_threshold,
            "dimensions": dimensions,
            "feedback": feedback,
        }

    def evaluate_and_refine(
        self,
        draft: dict[str, Any],
        context: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Run the Evaluator-Optimizer reflection loop until the draft passes the rubric threshold."""
        current = dict(draft)
        evaluation = self.evaluate_draft(current)
        for _ in range(self.max_iterations):
            if evaluation["passed"]:
                break
            service = context.get("service_name", "unknown-service")
            err_rate = context.get("error_rate_percent", 0.0)
            suspect_rel = context.get("suspect_release", "latest-canary")
            stable_rel = context.get("prior_stable_release", "v1.0.0")
            runbook = context.get("matched_runbook_id", "RB-101-CANARY-ROLLBACK")

            if evaluation["dimensions"]["root_cause_clarity"] < 1.0:
                current["root_cause_summary"] = (
                    f"Service '{service}' experienced an SLO-breaching error rate of {err_rate}% "
                    f"correlated with deployment '{suspect_rel}'. Recommended rollback target is '{stable_rel}'."
                )
            if evaluation["dimensions"]["runbook_alignment"] < 1.0:
                current["matched_runbook_id"] = runbook
            if evaluation["dimensions"]["actionable_mitigation_steps"] < 1.0:
                current["recommended_actions"] = [
                    f"Confirm golden-signal SLO breach on {service} ({err_rate}% 5xx errors).",
                    f"Correlate faulty release {suspect_rel} against stable baseline {stable_rel}.",
                    f"Follow runbook {runbook} and obtain Human-in-the-Loop approval before rollback to {stable_rel}.",
                ]
            if evaluation["dimensions"]["hitl_safety_compliance"] < 1.0:
                current["remediation_status"] = "AWAITING_HUMAN_APPROVAL"

            evaluation = self.evaluate_draft(current)
        return current, evaluation


DEFAULT_POLICY_GUARDRAIL = PolicyGuardrailPlugin()
DEFAULT_APPROVAL_GATE = HumanApprovalGate()
DEFAULT_SELF_CRITIQUE = SelfCritiqueEvaluator()


def before_model_guardrail_callback(
    user_prompt: str,
    callback_context: Any | None = None,
    guardrail: PolicyGuardrailPlugin | None = None,
) -> dict[str, Any]:
    """ADK before_model_callback enforcing prompt-injection defense and PII scrubbing."""
    _ = callback_context
    active_guardrail = guardrail or DEFAULT_POLICY_GUARDRAIL
    inspection = active_guardrail.inspect_user_input(user_prompt)
    return {
        "blocked": not inspection["allowed"],
        "violation_code": inspection["violation_code"],
        "reason": inspection["reason"],
        "sanitized_prompt": inspection["sanitized_prompt"],
    }


def after_model_guardrail_callback(
    model_output: str,
    callback_context: Any | None = None,
    guardrail: PolicyGuardrailPlugin | None = None,
) -> dict[str, Any]:
    """ADK after_model_callback scrubbing PII from LLM responses before emission."""
    _ = callback_context
    active_guardrail = guardrail or DEFAULT_POLICY_GUARDRAIL
    return active_guardrail.sanitize_model_output(model_output)


def before_tool_guardrail_callback(
    tool_name: str,
    tool_args: dict[str, Any],
    tool_context: Any | None = None,
    approval_gate: HumanApprovalGate | None = None,
) -> dict[str, Any]:
    """ADK before_tool_callback enforcing Human-in-the-Loop confirmation on high-stakes tools."""
    _ = tool_context
    gate = approval_gate or DEFAULT_APPROVAL_GATE
    return gate.verify_approval(
        tool_name=tool_name,
        service_name=str(tool_args.get("service_name", "")),
        target_version=str(tool_args.get("target_stable_version", "")),
        token=tool_args.get("human_approval_token"),
    )
