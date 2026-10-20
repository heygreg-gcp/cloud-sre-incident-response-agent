"""Automated Golden-Dataset Regression Evaluation Suite tests."""

from __future__ import annotations

import pathlib

import pytest

from sre_agent.evaluator import GoldenDatasetEvaluator


@pytest.mark.asyncio
async def test_golden_dataset_evaluation_suite_meets_regression_thresholds() -> None:
    """Verify Category 5 criterion: Automated Evaluation Suite against golden_dataset.json."""
    dataset_path = (
        pathlib.Path(__file__).resolve().parent / "eval" / "golden_dataset.json"
    )
    evaluator = GoldenDatasetEvaluator(dataset_path=str(dataset_path))
    summary = await evaluator.run_suite()

    assert summary["total_cases"] == 5
    assert summary["passed_cases"] == 5
    assert summary["failed_cases"] == 0
    assert summary["aggregate_score"] >= summary["minimum_pass_score"]
    for case_result in summary["case_results"]:
        assert case_result["passed"] is True, f"Case {case_result['case_id']} failed: {case_result}"
        assert case_result["pii_leak_detected"] is False
        assert case_result["trajectory_recall"] == 1.0
