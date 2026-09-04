"""Leakage-safe evaluation metrics for advisory anomaly detectors.

Thresholds are declared here, before any adapter is written. Daily windows are
the cohort grain: two windows of delay equals one missed daily job plus the
next. Top-5 is a small analyst review budget. A 0.60 baseline floor is 3/5
true endpoints in that budget. A +0.10 Isolation Forest lift is a material
effect, not a noisy 0.01 benchmark win.
"""

from __future__ import annotations

import math
import random
import statistics
from collections.abc import Mapping, Sequence

from securemail.domain.ml.models import (
    FEATURE_SCHEMA_VERSION,
    CohortLabels,
    DetectorEvaluation,
    EndpointWindow,
    EvaluationReport,
    GateResults,
    SeededEvent,
    WindowScore,
)

DETECTION_DELAY_WINDOWS = 2
TOP_K = 5
BASELINE_PRECISION_FLOOR = 0.60
ISOLATION_FOREST_PRECISION_LIFT = 0.10
P90_DELAY_SLACK_WINDOWS = 1
ALERT_RATE_REGRESSION_FACTOR = 1.10
MIN_HISTORY_WINDOWS = 14
WARMUP_DAYS = 28
MIN_SESSION_COUNT = 10
BOOTSTRAP_SAMPLES = 1000
BOOTSTRAP_SEED = 20260904
NULL_SCORE_SEED = 20260904
INCOMPLETE_RATE_GATE = 0.40

_NULL_DIGEST = "0" * 64


def true_event_endpoints(labels: CohortLabels) -> frozenset[str]:
    return frozenset(event.endpoint_id for event in labels.events)


def event_active_on_day(event: SeededEvent, day_index: int) -> bool:
    return event.start_day <= day_index <= event.end_day


def is_eval_day(day_index: int, warmup_days: int = WARMUP_DAYS) -> bool:
    return day_index >= warmup_days


def labeled_days(labels: CohortLabels) -> frozenset[tuple[str, int]]:
    days: set[tuple[str, int]] = set()
    for event in labels.events:
        for day in range(event.start_day, event.end_day + 1):
            days.add((event.endpoint_id, day))
    return frozenset(days)


def maintenance_days(labels: CohortLabels) -> frozenset[tuple[str, int]]:
    days: set[tuple[str, int]] = set()
    for window in labels.maintenance:
        for day in range(window.start_day, window.end_day + 1):
            days.add((window.endpoint_id, day))
    return frozenset(days)


def _eligible_scores(
    scores: Sequence[WindowScore],
    *,
    warmup_days: int = WARMUP_DAYS,
) -> list[WindowScore]:
    return [
        item
        for item in scores
        if is_eval_day(item.day_index, warmup_days)
        and item.skip_reason is None
        and not item.suppressed
    ]


def peak_scores_by_endpoint(scores: Sequence[WindowScore]) -> dict[str, WindowScore]:
    peaks: dict[str, WindowScore] = {}
    for item in _eligible_scores(scores):
        current = peaks.get(item.endpoint_id)
        if current is None or item.score > current.score:
            peaks[item.endpoint_id] = item
    return peaks


def precision_at_k(
    scores: Sequence[WindowScore],
    labels: CohortLabels,
    *,
    k: int = TOP_K,
    exclude_endpoints: frozenset[str] | None = None,
) -> tuple[float, list[str]]:
    """Event-level precision@K: one peak score per endpoint, then top-K."""

    excluded = exclude_endpoints or frozenset()
    true_ids = true_event_endpoints(labels)
    peaks = [
        item
        for item in peak_scores_by_endpoint(scores).values()
        if item.endpoint_id not in excluded
    ]
    ranked = sorted(peaks, key=lambda item: (-item.score, item.endpoint_id))
    top = ranked[:k]
    ids = [item.endpoint_id for item in top]
    if not ids:
        return 0.0, []
    hits = sum(1 for endpoint_id in ids if endpoint_id in true_ids)
    return hits / k, ids


def detection_delays(
    scores: Sequence[WindowScore],
    labels: CohortLabels,
    *,
    max_delay: int = DETECTION_DELAY_WINDOWS,
) -> dict[str, int | None]:
    """First threshold crossing at or after injection, else None."""

    by_key: dict[tuple[str, int], WindowScore] = {}
    for item in scores:
        if item.skip_reason is not None or item.suppressed:
            continue
        by_key[(item.endpoint_id, item.day_index)] = item

    delays: dict[str, int | None] = {}
    for event in labels.events:
        found: int | None = None
        last = event.start_day + max_delay
        for day in range(event.start_day, last + 1):
            scored = by_key.get((event.endpoint_id, day))
            if scored is not None and scored.above_threshold:
                found = day - event.start_day
                break
        delays[event.event_id] = found
    return delays


def _delay_values(delays: Mapping[str, int | None]) -> list[int]:
    return [value for value in delays.values() if value is not None]


def median_delay(delays: Mapping[str, int | None]) -> float | None:
    values = _delay_values(delays)
    if not values:
        return None
    return float(statistics.median(values))


def percentile(values: Sequence[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (len(ordered) - 1) * q
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return float(ordered[low])
    weight = rank - low
    return float(ordered[low] * (1.0 - weight) + ordered[high] * weight)


def p90_delay(delays: Mapping[str, int | None]) -> float | None:
    values = [float(item) for item in _delay_values(delays)]
    return percentile(values, 0.90)


def _endpoint_day_population(
    windows: Sequence[EndpointWindow],
    *,
    warmup_days: int = WARMUP_DAYS,
) -> list[tuple[str, int]]:
    return [
        (item.endpoint_id, item.day_index)
        for item in windows
        if is_eval_day(item.day_index, warmup_days) and not item.is_new_endpoint
    ]


def alert_rates(
    scores: Sequence[WindowScore],
    windows: Sequence[EndpointWindow],
    labels: CohortLabels,
    *,
    warmup_days: int = WARMUP_DAYS,
) -> tuple[float, float, float, int]:
    """Alerts / 1000 endpoint-days, plus clean and maintenance rates."""

    population = _endpoint_day_population(windows, warmup_days=warmup_days)
    if not population:
        return 0.0, 0.0, 0.0, 0

    alert_keys = {
        (item.endpoint_id, item.day_index)
        for item in scores
        if item.above_threshold and not item.suppressed and item.skip_reason is None
    }
    labeled = labeled_days(labels)
    maintained = maintenance_days(labels)
    new_endpoints = frozenset(labels.new_endpoints)

    alerts = 0
    clean_alerts = 0
    clean_days = 0
    maintenance_alerts = 0
    maintenance_pop = 0
    new_alerts = 0
    for endpoint_id, day_index in population:
        key = (endpoint_id, day_index)
        fired = key in alert_keys
        if fired:
            alerts += 1
        if key in maintained:
            maintenance_pop += 1
            if fired:
                maintenance_alerts += 1
        elif key not in labeled:
            clean_days += 1
            if fired:
                clean_alerts += 1
        if endpoint_id in new_endpoints and fired:
            new_alerts += 1

    per_thousand = 1000.0 * alerts / len(population)
    clean_rate = (clean_alerts / clean_days) if clean_days else 0.0
    maintenance_rate = (maintenance_alerts / maintenance_pop) if maintenance_pop else 0.0
    return per_thousand, clean_rate, maintenance_rate, new_alerts


def summarize_detector(
    scores: Sequence[WindowScore],
    windows: Sequence[EndpointWindow],
    labels: CohortLabels,
    *,
    detector: str,
    model_digest: str,
    k: int = TOP_K,
) -> DetectorEvaluation:
    excluded = frozenset(labels.new_endpoints)
    precision, ranked = precision_at_k(scores, labels, k=k, exclude_endpoints=excluded)
    delays = detection_delays(scores, labels)
    per_thousand, clean_rate, maintenance_rate, new_alerts = alert_rates(scores, windows, labels)
    return DetectorEvaluation(
        detector=detector,
        model_digest=model_digest,
        precision_at_k=precision,
        k=k,
        detection_delays=delays,
        median_delay=median_delay(delays),
        p90_delay=p90_delay(delays),
        alerts_per_1000_endpoint_days=per_thousand,
        clean_alert_rate=clean_rate,
        maintenance_alert_rate=maintenance_rate,
        new_endpoint_alert_count=new_alerts,
        ranked_endpoint_ids=ranked,
    )


def paired_bootstrap_lift(
    baseline: Sequence[WindowScore],
    challenger: Sequence[WindowScore],
    labels: CohortLabels,
    *,
    k: int = TOP_K,
    samples: int = BOOTSTRAP_SAMPLES,
    seed: int = BOOTSTRAP_SEED,
) -> tuple[float, float, float]:
    """Paired event-level bootstrap of precision@K lift. Returns (mean, ci_low, ci_high).

    Labeled true-event and jitter endpoints stay in every replicate so the
    comparison is paired at event level. Remaining endpoints are resampled.
    The reported interval is a one-sided 95% superiority bound (5th/95th).
    """

    excluded = frozenset(labels.new_endpoints)
    true_ids = true_event_endpoints(labels)
    baseline_peaks = {
        endpoint_id: item.score
        for endpoint_id, item in peak_scores_by_endpoint(baseline).items()
        if endpoint_id not in excluded
    }
    challenger_peaks = {
        endpoint_id: item.score
        for endpoint_id, item in peak_scores_by_endpoint(challenger).items()
        if endpoint_id not in excluded
    }
    endpoints = sorted(set(baseline_peaks) | set(challenger_peaks))
    if not endpoints:
        return 0.0, 0.0, 0.0

    rng = random.Random(seed)
    anchors = sorted((true_ids | frozenset(labels.jitter_endpoints)) & set(endpoints))
    fillers = [endpoint_id for endpoint_id in endpoints if endpoint_id not in anchors]
    filler_budget = max(0, len(endpoints) - len(anchors))

    def _precision(peak_map: Mapping[str, float], sample: Sequence[str]) -> float:
        ranked = sorted(
            sample,
            key=lambda endpoint_id: (-peak_map.get(endpoint_id, 0.0), endpoint_id),
        )
        unique: list[str] = []
        for endpoint_id in ranked:
            if endpoint_id not in unique:
                unique.append(endpoint_id)
            if len(unique) >= k:
                break
        if not unique:
            return 0.0
        return sum(1 for endpoint_id in unique if endpoint_id in true_ids) / k

    lifts: list[float] = []
    for _ in range(samples):
        sampled_fillers = (
            [fillers[rng.randrange(len(fillers))] for _ in range(filler_budget)] if fillers else []
        )
        sample = [*anchors, *sampled_fillers]
        lifts.append(_precision(challenger_peaks, sample) - _precision(baseline_peaks, sample))
    mean = sum(lifts) / len(lifts)
    # One-sided 95% interval for a superiority test (lift > 0).
    low = percentile(lifts, 0.05)
    high = percentile(lifts, 0.95)
    assert low is not None and high is not None
    return mean, low, high


def null_scores(
    windows: Sequence[EndpointWindow], *, seed: int = NULL_SCORE_SEED
) -> list[WindowScore]:
    """Uninformative ranking: seeded random scores, no evidence linkage."""

    rng = random.Random(seed)
    scores: list[WindowScore] = []
    for window in windows:
        score = rng.random()
        scores.append(
            WindowScore(
                endpoint_id=window.endpoint_id,
                day_index=window.day_index,
                detector="null",
                score=score,
                threshold=1.1,
                above_threshold=False,
                suppressed=window.in_maintenance,
                skip_reason=None,
                percentile=None,
                contributions=[],
                reason="null ranking; not an advisory output",
                model_digest=_NULL_DIGEST,
                feature_schema_version=FEATURE_SCHEMA_VERSION,
            )
        )
    return scores


def _univariate_ids(labels: CohortLabels) -> list[str]:
    return [event.event_id for event in labels.events if event.kind.value == "univariate"]


def _merge_delays(
    left: Mapping[str, int | None],
    right: Mapping[str, int | None],
) -> dict[str, int | None]:
    merged: dict[str, int | None] = {}
    for key in set(left) | set(right):
        first = left.get(key)
        second = right.get(key)
        if first is None:
            merged[key] = second
        elif second is None:
            merged[key] = first
        else:
            merged[key] = min(first, second)
    return merged


def _subset_delays(
    delays: Mapping[str, int | None], event_ids: Sequence[str]
) -> dict[str, int | None]:
    return {event_id: delays.get(event_id) for event_id in event_ids}


def _delay_gate(baseline: DetectorEvaluation, labels: CohortLabels) -> bool:
    univariate = _univariate_ids(labels)
    if not univariate:
        return False
    for event_id in univariate:
        delay = baseline.detection_delays.get(event_id)
        if delay is None or delay > DETECTION_DELAY_WINDOWS:
            return False
    return True


def compare_detectors(
    *,
    windows: Sequence[EndpointWindow],
    labels: CohortLabels,
    baseline: Sequence[WindowScore],
    challenger: Sequence[WindowScore] | None,
    baseline_digest: str,
    challenger_digest: str | None,
    cohort_id: str,
) -> EvaluationReport:
    null_eval = summarize_detector(
        null_scores(windows),
        windows,
        labels,
        detector="null",
        model_digest=_NULL_DIGEST,
    )
    baseline_eval = summarize_detector(
        baseline, windows, labels, detector="baseline", model_digest=baseline_digest
    )
    challenger_eval: DetectorEvaluation | None = None
    lift: float | None = None
    ci_low: float | None = None
    ci_high: float | None = None
    if challenger is not None and challenger_digest is not None:
        challenger_eval = summarize_detector(
            challenger,
            windows,
            labels,
            detector="isolation_forest",
            model_digest=challenger_digest,
        )
        lift = challenger_eval.precision_at_k - baseline_eval.precision_at_k
        _, ci_low, ci_high = paired_bootstrap_lift(baseline, challenger, labels)

    delay_ok = _delay_gate(baseline_eval, labels)
    baseline_floor = baseline_eval.precision_at_k >= BASELINE_PRECISION_FLOOR
    beats_null = baseline_eval.precision_at_k > null_eval.precision_at_k + 1e-12

    lift_ok = False
    ci_ok = False
    median_ok = False
    p90_ok = False
    alert_ok = False
    if challenger_eval is not None and lift is not None and ci_low is not None:
        fused_delays = _merge_delays(
            baseline_eval.detection_delays, challenger_eval.detection_delays
        )
        univariate = _univariate_ids(labels)
        baseline_univ = _subset_delays(baseline_eval.detection_delays, univariate)
        challenger_univ = _subset_delays(fused_delays, univariate)
        challenger_eval = challenger_eval.model_copy(
            update={
                "detection_delays": fused_delays,
                "median_delay": median_delay(challenger_univ),
                "p90_delay": p90_delay(challenger_univ),
            }
        )
        lift_ok = lift >= ISOLATION_FOREST_PRECISION_LIFT - 1e-12
        ci_ok = ci_low > 0.0
        base_median = median_delay(baseline_univ)
        cand_median = median_delay(challenger_univ)
        base_p90 = p90_delay(baseline_univ)
        cand_p90 = p90_delay(challenger_univ)
        if base_median is None:
            median_ok = cand_median is None
        elif cand_median is None:
            median_ok = False
        else:
            median_ok = cand_median <= base_median + 1e-12
        if base_p90 is None:
            p90_ok = cand_p90 is None
        elif cand_p90 is None:
            p90_ok = False
        else:
            p90_ok = cand_p90 <= base_p90 + P90_DELAY_SLACK_WINDOWS
        alert_ok = challenger_eval.clean_alert_rate <= (
            baseline_eval.clean_alert_rate * ALERT_RATE_REGRESSION_FACTOR + 1e-12
        ) and challenger_eval.maintenance_alert_rate <= (
            baseline_eval.maintenance_alert_rate * ALERT_RATE_REGRESSION_FACTOR + 1e-12
        )

    gates = GateResults(
        baseline_precision_floor=baseline_floor,
        baseline_beats_null=beats_null,
        detection_delay=delay_ok,
        challenger_precision_lift=lift_ok,
        lift_ci_excludes_zero=ci_ok,
        median_delay_no_worse=median_ok,
        p90_delay_within_slack=p90_ok,
        alert_rate_regression=alert_ok,
    )
    return EvaluationReport(
        cohort_id=cohort_id,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        null_detector=null_eval,
        baseline=baseline_eval,
        challenger=challenger_eval,
        precision_lift=lift,
        lift_ci_low=ci_low,
        lift_ci_high=ci_high,
        gates=gates,
    )
