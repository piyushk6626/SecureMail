"""Advisory history thresholds do not imply a clean baseline."""

from __future__ import annotations

from tests.support.fixture_harness import load_golden_report

from securemail.adapters.ml.baselines import BaselineAnomalyScorer
from securemail.application.advisory_pipeline import (
    attach_advisories_with_history,
    extract_endpoint_windows,
)
from securemail.domain.ml.evaluation import ISOLATION_FOREST_MIN_TRAIN_WINDOWS, MIN_HISTORY_WINDOWS
from securemail.domain.reports.schema import CanonicalReport


def test_empty_history_emits_insufficient_history_not_none() -> None:
    report = CanonicalReport.model_validate(load_golden_report())
    findings = list(report.evidence.findings)
    updated, windows = attach_advisories_with_history(
        report,
        scorers=(BaselineAnomalyScorer(),),
        history=(),
        cohort="local",
    )
    assert updated.evidence.findings == findings
    assert updated.evidence is report.evidence
    assert any(item.code == "ADVISORY_INSUFFICIENT_HISTORY" for item in updated.advisory.items)
    assert all(item.code != "ADVISORY_NONE" for item in updated.advisory.items)
    assert windows


def test_history_below_baseline_threshold_stays_insufficient() -> None:
    report = CanonicalReport.model_validate(load_golden_report())
    seed = extract_endpoint_windows(report.evidence)
    history = [
        item.model_copy(update={"day_index": index, "site_id": "local"})
        for index, item in enumerate(seed)
    ]
    assert len(history) < MIN_HISTORY_WINDOWS
    updated, _windows = attach_advisories_with_history(
        report,
        scorers=(BaselineAnomalyScorer(),),
        history=history,
        cohort="local",
    )
    assert updated.advisory.items[0].code == "ADVISORY_INSUFFICIENT_HISTORY"


def test_baseline_ready_keeps_isolation_forest_insufficient() -> None:
    report = CanonicalReport.model_validate(load_golden_report())
    seed = extract_endpoint_windows(report.evidence)
    history = []
    day_index = 0
    while len(history) < MIN_HISTORY_WINDOWS:
        for item in seed:
            history.append(item.model_copy(update={"day_index": day_index, "site_id": "local"}))
            day_index += 1
            if len(history) >= MIN_HISTORY_WINDOWS:
                break
    assert MIN_HISTORY_WINDOWS <= len(history) < ISOLATION_FOREST_MIN_TRAIN_WINDOWS
    updated, _windows = attach_advisories_with_history(
        report,
        scorers=(BaselineAnomalyScorer(),),
        history=history,
        cohort="local",
    )
    codes = [item.code for item in updated.advisory.items]
    assert "ADVISORY_INSUFFICIENT_HISTORY" in codes
    assert updated.evidence.findings == report.evidence.findings
