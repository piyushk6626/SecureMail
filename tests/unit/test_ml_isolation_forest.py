"""Isolation Forest must beat the committed baseline gate on the locked cohort."""

from __future__ import annotations

from collections.abc import Sequence

import pytest
from tests.support.synthetic_cohorts import generate_locked_cohort

from securemail.adapters.ml.baselines import BaselineAnomalyScorer
from securemail.adapters.ml.isolation_forest import IsolationForestScorer
from securemail.domain.ml.evaluation import (
    ISOLATION_FOREST_PRECISION_LIFT,
    compare_detectors,
    precision_at_k,
)
from securemail.domain.ml.models import (
    KNOWN_EVIDENCE_FIELDS,
    CohortLabels,
    CohortManifest,
    EndpointWindow,
    WindowScore,
)

pytest.importorskip("sklearn")


@pytest.fixture(scope="module")
def locked_scores() -> tuple[
    list[EndpointWindow],
    CohortLabels,
    CohortManifest,
    Sequence[WindowScore],
    Sequence[WindowScore],
    BaselineAnomalyScorer,
    IsolationForestScorer,
]:
    windows, labels, manifest = generate_locked_cohort()
    baseline = BaselineAnomalyScorer()
    challenger = IsolationForestScorer()
    return (
        windows,
        labels,
        manifest,
        baseline.score_windows(windows),
        challenger.score_windows(windows),
        baseline,
        challenger,
    )


def test_isolation_forest_beats_baseline_gate(
    locked_scores: tuple[
        list[EndpointWindow],
        CohortLabels,
        CohortManifest,
        Sequence[WindowScore],
        Sequence[WindowScore],
        BaselineAnomalyScorer,
        IsolationForestScorer,
    ],
) -> None:
    windows, labels, manifest, baseline_scores, challenger_scores, baseline, challenger = (
        locked_scores
    )
    report = compare_detectors(
        windows=windows,
        labels=labels,
        baseline=baseline_scores,
        challenger=challenger_scores,
        baseline_digest=baseline.model_digest,
        challenger_digest=challenger.model_digest,
        cohort_id=manifest.cohort_id,
    )
    excluded = frozenset(labels.new_endpoints)
    base_p, base_ranked = precision_at_k(baseline_scores, labels, exclude_endpoints=excluded)
    if_p, if_ranked = precision_at_k(challenger_scores, labels, exclude_endpoints=excluded)
    assert report.gates.baseline_precision_floor, report.model_dump(mode="json")
    assert report.gates.baseline_beats_null
    assert report.gates.detection_delay
    assert if_p - base_p >= ISOLATION_FOREST_PRECISION_LIFT - 1e-12
    assert report.precision_lift is not None
    assert report.lift_ci_low is not None and report.lift_ci_low > 0.0
    assert report.gates.challenger_precision_lift, {
        "baseline": base_p,
        "isolation_forest": if_p,
        "baseline_ranked": base_ranked,
        "if_ranked": if_ranked,
        "gates": report.gates.model_dump(mode="json"),
    }
    assert report.gates.lift_ci_excludes_zero
    assert report.gates.median_delay_no_worse
    assert report.gates.p90_delay_within_slack
    assert report.gates.alert_rate_regression
    assert report.gates.all_passed


def test_isolation_forest_reasons_cite_evidence_fields(
    locked_scores: tuple[
        list[EndpointWindow],
        CohortLabels,
        CohortManifest,
        Sequence[WindowScore],
        Sequence[WindowScore],
        BaselineAnomalyScorer,
        IsolationForestScorer,
    ],
) -> None:
    _windows, _labels, _manifest, _baseline_scores, challenger_scores, _baseline, _challenger = (
        locked_scores
    )
    alerts = [item for item in challenger_scores if item.above_threshold]
    assert alerts
    for item in alerts:
        assert "anomaly detected" not in item.reason.lower()
        assert any(field in item.reason for field in KNOWN_EVIDENCE_FIELDS)


def test_isolation_forest_explanations_are_faithful(
    locked_scores: tuple[
        list[EndpointWindow],
        CohortLabels,
        CohortManifest,
        Sequence[WindowScore],
        Sequence[WindowScore],
        BaselineAnomalyScorer,
        IsolationForestScorer,
    ],
) -> None:
    windows, _labels, _manifest, _baseline_scores, original, _baseline, scorer = locked_scores
    alert = next(
        item
        for item in original
        if item.above_threshold and item.contributions and item.skip_reason is None
    )
    by_key = {(window.endpoint_id, window.day_index): window for window in windows}
    source = by_key[(alert.endpoint_id, alert.day_index)]
    changes: dict[str, float] = {}
    for contrib in alert.contributions:
        if isinstance(contrib.reference, float) and hasattr(source, contrib.feature):
            changes[contrib.feature] = contrib.reference
    assert changes
    restored = [
        window.model_copy(update=changes)
        if (window.endpoint_id, window.day_index) == (alert.endpoint_id, alert.day_index)
        else window
        for window in windows
    ]
    mutated = scorer.score_windows(restored)
    restored_score = next(
        item.score
        for item in mutated
        if item.endpoint_id == alert.endpoint_id and item.day_index == alert.day_index
    )
    assert restored_score <= alert.score + 1e-9


def test_isolation_forest_is_past_only(
    locked_scores: tuple[
        list[EndpointWindow],
        CohortLabels,
        CohortManifest,
        Sequence[WindowScore],
        Sequence[WindowScore],
        BaselineAnomalyScorer,
        IsolationForestScorer,
    ],
) -> None:
    windows, _labels, _manifest, _baseline_scores, original, _baseline, scorer = locked_scores
    scrambled = [
        window
        if window.day_index <= 40
        else window.model_copy(update={"tls10_share": 1.0, "tls13_share": 0.0, "tls12_share": 0.0})
        for window in windows
    ]
    mutated = scorer.score_windows(scrambled)
    before = {
        (item.endpoint_id, item.day_index): round(item.score, 10)
        for item in original
        if item.day_index == 40
    }
    after = {
        (item.endpoint_id, item.day_index): round(item.score, 10)
        for item in mutated
        if item.day_index == 40
    }
    assert before == after
