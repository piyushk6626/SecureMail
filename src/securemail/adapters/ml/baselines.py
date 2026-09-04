"""Median/MAD, categorical-rarity, and Page-Hinkley baseline scorers."""

from __future__ import annotations

import hashlib
import json
import math
import statistics
from collections import defaultdict
from collections.abc import Sequence

from securemail.domain.ml.evaluation import (
    INCOMPLETE_RATE_GATE,
    MIN_HISTORY_WINDOWS,
    MIN_SESSION_COUNT,
)
from securemail.domain.ml.models import (
    EVIDENCE_FIELD_FOR_FEATURE,
    FEATURE_SCHEMA_VERSION,
    MAD_FEATURE_NAMES,
    EndpointWindow,
    FeatureContribution,
    WindowScore,
    categorical_value,
    numeric_value,
)

MAD_SCALE = 1.4826
MAD_FLOOR = 0.01
Z_CAP = 30.0
Z_THRESHOLD = 3.5
PAGE_HINKLEY_DELTA = 0.02
PAGE_HINKLEY_LAMBDA = 0.5
RARITY_FEATURES: tuple[str, ...] = ("issuer_id", "dominant_tls_version")

_BASELINE_PARAMS = {
    "mad_scale": MAD_SCALE,
    "mad_floor": MAD_FLOOR,
    "z_threshold": Z_THRESHOLD,
    "page_hinkley_delta": PAGE_HINKLEY_DELTA,
    "page_hinkley_lambda": PAGE_HINKLEY_LAMBDA,
    "min_history_windows": MIN_HISTORY_WINDOWS,
    "feature_schema_version": FEATURE_SCHEMA_VERSION,
}


def baseline_model_digest() -> str:
    payload = json.dumps({"name": "baseline", "params": _BASELINE_PARAMS}, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def median_mad(values: Sequence[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    med = float(statistics.median(values))
    mad = float(statistics.median([abs(item - med) for item in values]))
    return med, mad


def robust_z(value: float, median: float, mad: float) -> float:
    scale = max(mad * MAD_SCALE, MAD_FLOOR)
    z_score = (value - median) / scale
    return max(-Z_CAP, min(Z_CAP, z_score))


def page_hinkley_score(history: Sequence[float], current: float) -> float:
    mean = 0.0
    statistic = 0.0
    count = 0
    for value in (*history, current):
        count += 1
        mean += (value - mean) / count
        statistic = max(0.0, statistic + value - mean - PAGE_HINKLEY_DELTA)
    return statistic / PAGE_HINKLEY_LAMBDA


def categorical_rarity(value: str, history: Sequence[str]) -> tuple[float, bool, int]:
    count = sum(1 for item in history if item == value)
    n_history = len(history)
    first_seen = n_history > 0 and count == 0
    score = -math.log((count + 0.5) / (n_history + 0.5))
    return score, first_seen, count


def skip_reason(window: EndpointWindow, history: Sequence[EndpointWindow]) -> str | None:
    if window.session_count < MIN_SESSION_COUNT:
        return "insufficient_support"
    if len(history) < MIN_HISTORY_WINDOWS:
        return "insufficient_history"
    if not window.capture_quality_ok:
        return "capture_quality"
    if window.incomplete_reconstruction_rate > INCOMPLETE_RATE_GATE:
        return "capture_quality"
    return None


def _peer_history(
    by_cohort: dict[tuple[str, str], list[EndpointWindow]],
    window: EndpointWindow,
) -> list[EndpointWindow]:
    series = by_cohort.get((window.site_id, window.protocol_role.value), [])
    return [item for item in series if item.day_index < window.day_index]


def _contributions(
    *,
    window: EndpointWindow,
    history: Sequence[EndpointWindow],
    peers: Sequence[EndpointWindow],
) -> list[FeatureContribution]:
    items: list[FeatureContribution] = []
    for name in MAD_FEATURE_NAMES:
        series = [numeric_value(item, name) for item in history]
        median, mad = median_mad(series)
        value = numeric_value(window, name)
        z_score = robust_z(value, median, mad)
        ph_score = page_hinkley_score(series, value)
        score = max(abs(z_score), ph_score)
        items.append(
            FeatureContribution(
                feature=name,
                evidence_field=EVIDENCE_FIELD_FOR_FEATURE[name],
                value=value,
                reference=median,
                score=score,
            )
        )
    catalog = peers if peers else history
    for name in RARITY_FEATURES:
        past_values = [categorical_value(item, name) for item in catalog]
        current = categorical_value(window, name)
        rarity, _first_seen, _count = categorical_rarity(current, past_values)
        items.append(
            FeatureContribution(
                feature=name,
                evidence_field=EVIDENCE_FIELD_FOR_FEATURE[name],
                value=current,
                reference=f"peer_count={_count}",
                score=rarity,
            )
        )
    items.sort(key=lambda item: (-item.score, item.feature))
    return items


def build_reason(contributions: Sequence[FeatureContribution], *, prefix: str | None = None) -> str:
    if not contributions:
        return "insufficient_history: session_count; field session.uid."
    parts: list[str] = []
    fields: list[str] = []
    for item in contributions[:3]:
        if isinstance(item.value, float) and isinstance(item.reference, float):
            parts.append(
                f"{item.feature} is {item.value:.4f} (trailing median {item.reference:.4f})"
            )
        else:
            parts.append(f"{item.feature} is {item.value} ({item.reference})")
        fields.append(item.evidence_field)
    unique_fields = ", ".join(dict.fromkeys(fields))
    body = f"{'; '.join(parts)}; fields {unique_fields}."
    if prefix:
        return f"{prefix} {body}"
    return body


def percentile_map(scores: Sequence[WindowScore]) -> dict[tuple[str, int], float]:
    by_day: dict[int, list[WindowScore]] = defaultdict(list)
    for item in scores:
        if item.skip_reason is None and not item.suppressed:
            by_day[item.day_index].append(item)
    mapped: dict[tuple[str, int], float] = {}
    for _day_index, items in by_day.items():
        ordered = sorted(item.score for item in items)
        n_items = len(ordered)
        for item in items:
            rank = sum(1 for value in ordered if value <= item.score)
            mapped[(item.endpoint_id, item.day_index)] = 100.0 * rank / n_items
    return mapped


class BaselineAnomalyScorer:
    """Per-endpoint robust statistics plus peer-group categorical rarity."""

    name = "baseline"

    def __init__(self) -> None:
        self._digest = baseline_model_digest()

    @property
    def model_digest(self) -> str:
        return self._digest

    def score_windows(self, windows: Sequence[EndpointWindow]) -> list[WindowScore]:
        by_endpoint: dict[str, list[EndpointWindow]] = defaultdict(list)
        by_cohort: dict[tuple[str, str], list[EndpointWindow]] = defaultdict(list)
        for window in windows:
            by_endpoint[window.endpoint_id].append(window)
            by_cohort[(window.site_id, window.protocol_role.value)].append(window)
        for series in by_endpoint.values():
            series.sort(key=lambda item: item.day_index)
        for series in by_cohort.values():
            series.sort(key=lambda item: item.day_index)

        scored: list[WindowScore] = []
        for window in windows:
            history = [
                item
                for item in by_endpoint[window.endpoint_id]
                if item.day_index < window.day_index
            ]
            skip = skip_reason(window, history)
            if window.in_maintenance:
                scored.append(
                    WindowScore(
                        endpoint_id=window.endpoint_id,
                        day_index=window.day_index,
                        detector=self.name,
                        score=0.0,
                        threshold=Z_THRESHOLD,
                        above_threshold=False,
                        suppressed=True,
                        skip_reason=None,
                        contributions=[],
                        reason=(
                            "maintenance window suppressed; field session.explicit_upgrade.state."
                        ),
                        model_digest=self._digest,
                        feature_schema_version=FEATURE_SCHEMA_VERSION,
                    )
                )
                continue
            if skip is not None:
                scored.append(
                    WindowScore(
                        endpoint_id=window.endpoint_id,
                        day_index=window.day_index,
                        detector=self.name,
                        score=0.0,
                        threshold=Z_THRESHOLD,
                        above_threshold=False,
                        skip_reason=skip,
                        contributions=[],
                        reason=f"{skip}: session_count; field session.uid.",
                        model_digest=self._digest,
                        feature_schema_version=FEATURE_SCHEMA_VERSION,
                    )
                )
                continue
            peers = _peer_history(by_cohort, window)
            contributions = _contributions(window=window, history=history, peers=peers)
            score = max((item.score for item in contributions), default=0.0)
            scored.append(
                WindowScore(
                    endpoint_id=window.endpoint_id,
                    day_index=window.day_index,
                    detector=self.name,
                    score=score,
                    threshold=Z_THRESHOLD,
                    above_threshold=score >= Z_THRESHOLD,
                    contributions=contributions[:3],
                    reason=build_reason(contributions[:3]),
                    model_digest=self._digest,
                    feature_schema_version=FEATURE_SCHEMA_VERSION,
                )
            )

        percentiles = percentile_map(scored)
        updated: list[WindowScore] = []
        for item in scored:
            percentile = percentiles.get((item.endpoint_id, item.day_index))
            updated.append(item.model_copy(update={"percentile": percentile}))
        return updated
