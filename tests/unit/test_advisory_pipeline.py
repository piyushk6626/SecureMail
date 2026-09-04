"""Advisory pipeline authority, feature extraction, and reason linkage."""

from __future__ import annotations

from tests.support.fixture_harness import load_golden_report
from tests.support.synthetic_cohorts import generate_locked_cohort

from securemail.adapters.ml.baselines import BaselineAnomalyScorer
from securemail.application.advisory_pipeline import (
    anomalies_from_scores,
    attach_advisories,
    extract_endpoint_windows,
)
from securemail.domain.ml.models import KNOWN_EVIDENCE_FIELDS
from securemail.domain.reports.schema import CanonicalReport


def test_advisory_does_not_change_deterministic_findings() -> None:
    report = CanonicalReport.model_validate(load_golden_report())
    before_findings = [item.model_dump(mode="json") for item in report.evidence.findings]
    before_evidence = report.evidence.model_dump(mode="json")
    updated = attach_advisories(report, scorers=(BaselineAnomalyScorer(),), cohort="capture")
    after_findings = [item.model_dump(mode="json") for item in updated.evidence.findings]
    after_evidence = updated.evidence.model_dump(mode="json")
    assert before_findings == after_findings
    assert before_evidence == after_evidence
    assert updated.evidence is report.evidence
    assert updated.advisory.present is True
    assert updated.advisory.items


def test_extract_windows_from_canonical_evidence() -> None:
    report = CanonicalReport.model_validate(load_golden_report())
    windows = extract_endpoint_windows(report.evidence)
    assert windows
    for window in windows:
        assert window.site_id == "capture"
        assert window.session_count >= 1


def test_anomaly_results_always_have_concrete_reasons() -> None:
    windows, _labels, _manifest = generate_locked_cohort()
    scores = BaselineAnomalyScorer().score_windows(windows)
    results = anomalies_from_scores(scores, cohort="cohort_seeded_v1")
    assert results
    for item in results:
        assert item.reason
        assert "anomaly detected" not in item.reason.lower()
        assert item.evidence_fields
        assert all(field in KNOWN_EVIDENCE_FIELDS for field in item.evidence_fields)
        assert any(field in item.reason for field in item.evidence_fields)
