"""Automated Golden-Dataset Evaluation Harness for AgentOps Regression Testing.

Implements Category 5 criterion: Automated Evaluation Suites — evaluates agent
tool trajectories, outcome schema accuracy, HITL guardrail compliance, and PII
redaction against `tests/eval/golden_dataset.json`.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

from sre_agent.agent import IncidentResponseOrchestrator
from sre_agent.guardrails import DEFAULT_APPROVAL_GATE
from sre_agent.observability import DEFAULT_INTENT_TRACKER


class GoldenDatasetEvaluator:
    """Runs static and behavioral regression evaluations against a golden incident dataset."""

    def __init__(self, dataset_path: str) -> None:
        self.dataset_path = pathlib.Path(dataset_path)
        self.orchestrator = IncidentResponseOrchestrator()

    def load_dataset(self) -> dict[str, Any]:
        """Load and parse the JSON golden evaluation dataset."""
        raw = self.dataset_path.read_text(encoding="utf-8")
        return dict(json.loads(raw))

    async def evaluate_case(self, case: dict[str, Any]) -> dict[str, Any]:
        """Execute a single golden test case and compute trajectory and outcome metrics."""
        case_id = str(case["case_id"])
        inp = dict(case["input"])
        expected = dict(case["expected"])
        session_id = str(inp["session_id"])

        approval_token: str | None = None
        if inp.get("issue_human_approval"):
            approval_token = DEFAULT_APPROVAL_GATE.issue_approval_token(
                service_name=str(inp["service_name"]),
                action="execute_production_rollback",
                target_version=str(inp.get("approval_target_version", "v2.4.1")),
            )

        report = await self.orchestrator.handle_incident(
            session_id=session_id,
            user_prompt=str(inp["user_prompt"]),
            service_name=str(inp["service_name"]),
            region=str(inp.get("region", "us-central1")),
            human_approval_token=approval_token,
        )
        await self.orchestrator.memory_consolidator.wait_for_all_pending()

        audit_trail = DEFAULT_INTENT_TRACKER.get_session_audit_trail(session_id)
        executed_tools = {entry["tool_name"] for entry in audit_trail}
        required_tools = set(expected.get("required_tools_called", []))

        if not required_tools:
            trajectory_recall = 1.0 if len(executed_tools) == 0 else 0.0
        else:
            matched_tools = len(required_tools & executed_tools)
            trajectory_recall = round(matched_tools / len(required_tools), 4)

        checks = {
            "severity_match": report.severity == expected["severity"],
            "slo_breached_match": report.slo_breached == expected["slo_breached"],
            "runbook_match": report.matched_runbook_id == expected["matched_runbook_id"],
            "remediation_status_match": (
                report.remediation_status == expected["remediation_status"]
            ),
            "trajectory_complete": trajectory_recall == 1.0,
        }

        serialized_report = json.dumps(report.model_dump())
        pii_tokens: list[str] = list(expected.get("must_not_contain_pii", []))
        pii_leak_detected = any(token in serialized_report for token in pii_tokens)
        checks["zero_pii_leak"] = not pii_leak_detected

        case_score = round(sum(1.0 for ok in checks.values() if ok) / len(checks), 4)
        return {
            "case_id": case_id,
            "passed": all(checks.values()),
            "case_score": case_score,
            "trajectory_recall": trajectory_recall,
            "pii_leak_detected": pii_leak_detected,
            "checks": checks,
            "report": report.model_dump(),
        }

    async def run_suite(self) -> dict[str, Any]:
        """Run all cases in the golden dataset and compute aggregate pass/fail metrics."""
        dataset = self.load_dataset()
        cases: list[dict[str, Any]] = list(dataset.get("cases", []))
        min_score = float(dataset.get("minimum_pass_score", 0.90))

        results: list[dict[str, Any]] = []
        for case in cases:
            res = await self.evaluate_case(case)
            results.append(res)

        passed_count = sum(1 for r in results if r["passed"])
        aggregate_score = (
            round(sum(float(r["case_score"]) for r in results) / len(results), 4)
            if results
            else 0.0
        )
        return {
            "suite_name": dataset.get("suite_name", "golden-eval"),
            "minimum_pass_score": min_score,
            "total_cases": len(results),
            "passed_cases": passed_count,
            "failed_cases": len(results) - passed_count,
            "aggregate_score": aggregate_score,
            "suite_passed": aggregate_score >= min_score and passed_count == len(results),
            "case_results": results,
        }
