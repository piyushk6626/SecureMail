"""Baseline median/MAD + rarity + change-point vs a null ranking."""

from __future__ import annotations

from tests.support.synthetic_cohorts import generate_locked_cohort

from securemail.adapters.ml.baselines import BaselineAnomalyScorer
from securemail.domain.ml.evaluation import (
    BASELINE_PRECISION_FLOOR,
    DETECTION_DELAY_WINDOWS,
    compare_detectors,
    detection_delays,
    null_scores,
    precision_at_k,
)
from securemail.domain.ml.models import KNOWN_EVIDENCE_FIELDS


def test_baseline_beats_null_and_meets_precision_floor() -> None:
    windows, labels, manifest = generate_locked_cohort()
    scorer = BaselineAnomalyScorer()
    scores = scorer.score_windows(windows)
    precision, ranked = precision_at_k(
        scores, labels, exclude_endpoints=frozenset(labels.new_endpoints)
    )
    null_precision, _null_ranked = precision_at_k(
        null_scores(windows), labels, exclude_endpoints=frozenset(labels.new_endpoints)
    )
    assert precision > null_precision
    assert precision >= BASELINE_PRECISION_FLOOR
    report = compare_detectors(
        windows=windows,
        labels=labels,
        baseline=scores,
        challenger=None,
        baseline_digest=scorer.model_digest,
        challenger_digest=None,
        cohort_id=manifest.cohort_id,
    )
    assert report.gates.baseline_beats_null
    assert report.gates.baseline_precision_floor
    assert ranked


def test_baseline_flags_univariate_events_within_delay() -> None:
    windows, labels, _manifest = generate_locked_cohort()
    scores = BaselineAnomalyScorer().score_windows(windows)
    delays = detection_delays(scores, labels)
    univariate = [event for event in labels.events if event.kind.value == "univariate"]
    assert univariate
    for event in univariate:
        delay = delays[event.event_id]
        assert delay is not None
        assert delay <= DETECTION_DELAY_WINDOWS


def test_baseline_reasons_cite_evidence_fields() -> None:
    windows, _labels, _manifest = generate_locked_cohort()
    scores = BaselineAnomalyScorer().score_windows(windows)
    alerts = [item for item in scores if item.above_threshold]
    assert alerts
    for item in alerts:
        assert "anomaly detected" not in item.reason.lower()
        assert any(field in item.reason for field in KNOWN_EVIDENCE_FIELDS)


def test_baseline_is_past_only() -> None:
    windows, _labels, _manifest = generate_locked_cohort()
    scorer = BaselineAnomalyScorer()
    original = scorer.score_windows(windows)
    scrambled = [
        window
        if window.day_index <= 40
        else window.model_copy(update={"tls10_share": 1.0, "tls13_share": 0.0, "tls12_share": 0.0})
        for window in windows
    ]
    mutated = scorer.score_windows(scrambled)
    before = {
        (item.endpoint_id, item.day_index): item.score for item in original if item.day_index == 40
    }
    after = {
        (item.endpoint_id, item.day_index): item.score for item in mutated if item.day_index == 40
    }
    assert before == after
