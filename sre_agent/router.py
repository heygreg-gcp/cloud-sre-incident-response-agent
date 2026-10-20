"""Strategic Model Router for Multi-Tier Gemini Selection.

Implements Category 3 criterion: Strategic Model Routing — dynamically routing
high-volume, latency-sensitive tasks (telemetry triage, log clustering, history
compaction) to `gemini-2.5-flash` and complex multi-hop reasoning tasks (root-cause
correlation, remediation planning, self-critique) to `gemini-2.5-pro`.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from sre_agent.observability import DEFAULT_LOGGER
from sre_agent.schemas import StrictSchemaModel

TaskCategory = Literal[
    "telemetry_triage",
    "log_anomaly_clustering",
    "history_compaction",
    "root_cause_analysis",
    "remediation_planning",
    "coordinator_synthesis",
]


class ModelRoutingDecision(StrictSchemaModel):
    """Structured record of a strategic model routing decision."""

    task_type: TaskCategory = Field(..., description="Evaluated agent task category.")
    selected_model: Literal["gemini-2.5-flash", "gemini-2.5-pro"] = Field(
        ..., description="Selected Gemini model identifier."
    )
    tier: Literal["FAST_LOW_LATENCY", "DEEP_REASONING"] = Field(
        ..., description="Operational tier classification."
    )
    rationale: str = Field(..., description="Engineering rationale for model selection.")


class StrategicModelRouter:
    """Routes sub-agent tasks to the optimal Gemini model tier based on complexity and latency budget."""

    FLASH_MODEL: Literal["gemini-2.5-flash"] = "gemini-2.5-flash"
    PRO_MODEL: Literal["gemini-2.5-pro"] = "gemini-2.5-pro"

    _FAST_TASKS: frozenset[str] = frozenset(
        {
            "telemetry_triage",
            "log_anomaly_clustering",
            "history_compaction",
        }
    )

    _REASONING_KEYWORDS: tuple[str, ...] = (
        "correlate",
        "root cause",
        "rollback",
        "multi-service",
        "synthesize",
        "remediation",
        "hypothesis",
    )

    def route_task(
        self,
        task_type: TaskCategory,
        prompt: str = "",
        session_id: str = "default-session",
    ) -> ModelRoutingDecision:
        """Select `gemini-2.5-flash` or `gemini-2.5-pro` for the given task and prompt."""
        lower_prompt = prompt.lower()
        high_complexity_signal = any(kw in lower_prompt for kw in self._REASONING_KEYWORDS)

        if task_type in self._FAST_TASKS and not (
            task_type != "telemetry_triage" and high_complexity_signal
        ):
            decision = ModelRoutingDecision(
                task_type=task_type,
                selected_model=self.FLASH_MODEL,
                tier="FAST_LOW_LATENCY",
                rationale=(
                    f"Task '{task_type}' is latency-sensitive structured extraction; "
                    f"routed to {self.FLASH_MODEL} for sub-second execution."
                ),
            )
        else:
            decision = ModelRoutingDecision(
                task_type=task_type,
                selected_model=self.PRO_MODEL,
                tier="DEEP_REASONING",
                rationale=(
                    f"Task '{task_type}' requires multi-hop causal reasoning and safety "
                    f"verification; routed to {self.PRO_MODEL}."
                ),
            )

        DEFAULT_LOGGER.log_event(
            event_type="STRATEGIC_MODEL_ROUTED",
            message=f"Routed {task_type} -> {decision.selected_model} ({decision.tier})",
            session_id=session_id,
            metadata=decision.model_dump(),
        )
        return decision
