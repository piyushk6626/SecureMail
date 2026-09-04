"""Step 10 evaluation constants, synthetic cohort, and metric helpers."""

from __future__ import annotations

from tests.support.synthetic_cohorts import (
    DEV_SEED,
    LOCKED_EVAL_SEED,
    generate_cohort,
    generate_locked_cohort,
)

from securemail.domain.ml.evaluation import (
    BASELINE_PRECISION_FLOOR,
    DETECTION_DELAY_WINDOWS,
    ISOLATION_FOREST_PRECISION_LIFT,
    TOP_K,
    WARMUP_DAYS,
    detection_delays,
    null_scores,
    precision_at_k,
    true_event_endpoints,
)


def test_thresholds_are_frozen() -> None:
    assert DETECTION_DELAY_WINDOWS == 2
    assert TOP_K == 5
    assert BASELINE_PRECISION_FLOOR == 0.60
    assert ISOLATION_FOREST_PRECISION_LIFT == 0.10
    assert WARMUP_DAYS == 28


def test_locked_and_dev_seeds_differ() -> None:
    assert LOCKED_EVAL_SEED != DEV_SEED
    locked = generate_cohort(seed=LOCKED_EVAL_SEED)
    held_out = generate_cohort(seed=DEV_SEED)
    assert locked != held_out


def test_locked_cohort_is_deterministic() -> None:
    first, labels, manifest = generate_locked_cohort()
    second, labels_again, manifest_again = generate_locked_cohort()
    assert first == second
    assert labels == labels_again
    assert manifest == manifest_again
    assert len(true_event_endpoints(labels)) == 5
    families = {event.kind.value for event in labels.events}
    assert families == {"univariate", "multivariate"}


def test_null_ranking_is_uninformative() -> None:
    windows, labels, _manifest = generate_locked_cohort()
    precision, ranked = precision_at_k(null_scores(windows), labels)
    assert precision <= BASELINE_PRECISION_FLOOR
    assert ranked


def test_detection_delay_helper_none_when_never_flagged() -> None:
    windows, labels, _manifest = generate_locked_cohort()
    delays = detection_delays(null_scores(windows), labels)
    assert all(value is None for value in delays.values())
