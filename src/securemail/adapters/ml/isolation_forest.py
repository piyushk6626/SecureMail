"""Isolation Forest challenger. Added only to beat the committed baseline gate."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Sequence
from typing import Any

from securemail.adapters.ml.baselines import (
    RARITY_FEATURES,
    Z_THRESHOLD,
    build_reason,
    categorical_rarity,
    median_mad,
    percentile_map,
    robust_z,
    skip_reason,
)
from securemail.domain.ml.models import (
    EVIDENCE_FIELD_FOR_FEATURE,
    FEATURE_SCHEMA_VERSION,
    MAD_FEATURE_NAMES,
    NUMERIC_FEATURE_NAMES,
    EndpointWindow,
    FeatureContribution,
    WindowScore,
    categorical_value,
    numeric_value,
)
from securemail.ports.ml import MlDependencyError

_IF_PARAMS: dict[str, int | float] = {
    "n_estimators": 80,
    "max_samples": 256,
    "random_state": 20260904,
    "threshold_quantile": 0.992,
    "min_train_windows": 40,
    "refit_every_days": 7,
}

_VERSION_BUCKETS: tuple[str, ...] = ("TLSv10", "TLSv12", "TLSv13", "other")


def isolation_forest_model_digest() -> str:
    payload = json.dumps(
        {
            "name": "isolation_forest",
            "params": {**_IF_PARAMS, "feature_schema_version": FEATURE_SCHEMA_VERSION},
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _load_sklearn() -> tuple[Any, Any]:
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest  # type: ignore[import-untyped]
    except ImportError as exc:
        raise MlDependencyError(
            "securemail evaluate-ml requires the optional ml extra (scikit-learn, numpy)"
        ) from exc
    return np, IsolationForest


def _eligible_history(series: Sequence[EndpointWindow], day_index: int) -> list[EndpointWindow]:
    return [item for item in series if item.day_index < day_index]


def _peer_history(
    by_cohort: dict[tuple[str, str], list[EndpointWindow]],
    window: EndpointWindow,
) -> list[EndpointWindow]:
    series = by_cohort.get((window.site_id, window.protocol_role.value), [])
    return [item for item in series if item.day_index < window.day_index]


def _version_bucket(value: str) -> str:
    if value in {"TLSv10", "TLSv12", "TLSv13"}:
        return value
    return "other"


def _raw_vector(
    window: EndpointWindow,
    history: Sequence[EndpointWindow],
    peers: Sequence[EndpointWindow],
) -> list[float]:
    values: list[float] = []
    catalog = peers if peers else history
    for name in NUMERIC_FEATURE_NAMES:
        values.append(numeric_value(window, name))
    for name in MAD_FEATURE_NAMES:
        series = [numeric_value(item, name) for item in history]
        median, mad = median_mad(series)
        values.append(abs(robust_z(numeric_value(window, name), median, mad)))
    for name in RARITY_FEATURES:
        past = [categorical_value(item, name) for item in catalog]
        rarity, first_seen, _count = categorical_rarity(categorical_value(window, name), past)
        values.append(rarity)
        values.append(1.0 if first_seen else 0.0)
    endpoint_issuers = [item.issuer_id for item in history]
    _rarity, endpoint_first, _count = categorical_rarity(window.issuer_id, endpoint_issuers)
    values.append(1.0 if endpoint_first else 0.0)
    version = _version_bucket(window.dominant_tls_version)
    for bucket in _VERSION_BUCKETS:
        values.append(1.0 if version == bucket else 0.0)
    return values


def _scale(matrix: list[list[float]]) -> tuple[list[list[float]], list[float], list[float]]:
    if not matrix:
        return [], [], []
    n_features = len(matrix[0])
    medians: list[float] = []
    mads: list[float] = []
    for column in range(n_features):
        values = [row[column] for row in matrix]
        median, mad = median_mad(values)
        medians.append(median)
        mads.append(max(mad, 1e-6))
    scaled = [
        [(row[index] - medians[index]) / mads[index] for index in range(n_features)]
        for row in matrix
    ]
    return scaled, medians, mads


def _apply_scale(
    vector: list[float], medians: Sequence[float], mads: Sequence[float]
) -> list[float]:
    return [(vector[index] - medians[index]) / mads[index] for index in range(len(vector))]


def _contributions(
    window: EndpointWindow, history: Sequence[EndpointWindow], peers: Sequence[EndpointWindow]
) -> list[FeatureContribution]:
    items: list[FeatureContribution] = []
    for name in NUMERIC_FEATURE_NAMES:
        series = [numeric_value(item, name) for item in history]
        median, _mad = median_mad(series)
        value = numeric_value(window, name)
        items.append(
            FeatureContribution(
                feature=name,
                evidence_field=EVIDENCE_FIELD_FOR_FEATURE[name],
                value=value,
                reference=median,
                score=abs(value - median),
            )
        )
    catalog = peers if peers else history
    for name in RARITY_FEATURES:
        past = [categorical_value(item, name) for item in catalog]
        current = categorical_value(window, name)
        rarity, _first, count = categorical_rarity(current, past)
        items.append(
            FeatureContribution(
                feature=name,
                evidence_field=EVIDENCE_FIELD_FOR_FEATURE[name],
                value=current,
                reference=f"peer_count={count}",
                score=rarity,
            )
        )
    items.sort(key=lambda item: (-item.score, item.feature))
    return items[:3]


class IsolationForestScorer:
    """Cohort-level Isolation Forest on endpoint-window rates and rarity."""

    name = "isolation_forest"

    def __init__(self) -> None:
        self._digest = isolation_forest_model_digest()

    @property
    def model_digest(self) -> str:
        return self._digest

    def score_windows(self, windows: Sequence[EndpointWindow]) -> list[WindowScore]:
        np, isolation_forest_cls = _load_sklearn()
        by_endpoint: dict[str, list[EndpointWindow]] = defaultdict(list)
        by_cohort: dict[tuple[str, str], list[EndpointWindow]] = defaultdict(list)
        for window in windows:
            by_endpoint[window.endpoint_id].append(window)
            by_cohort[(window.site_id, window.protocol_role.value)].append(window)
        for series in by_endpoint.values():
            series.sort(key=lambda item: item.day_index)
        for series in by_cohort.values():
            series.sort(key=lambda item: item.day_index)

        days = sorted({window.day_index for window in windows})
        models: dict[int, tuple[Any, list[float], list[float], float]] = {}

        def _trainable(window: EndpointWindow) -> bool:
            history = _eligible_history(by_endpoint[window.endpoint_id], window.day_index)
            if window.in_maintenance or skip_reason(window, history) is not None:
                return False
            return True

        last_fit_day = -10_000
        last_fit: tuple[Any, list[float], list[float], float] | None = None
        refit_every = int(_IF_PARAMS["refit_every_days"])
        for day_index in days:
            if last_fit is not None and day_index - last_fit_day < refit_every:
                models[day_index] = last_fit
                continue
            train_windows = [
                window for window in windows if window.day_index < day_index and _trainable(window)
            ]
            vectors = [
                _raw_vector(
                    window,
                    _eligible_history(by_endpoint[window.endpoint_id], window.day_index),
                    _peer_history(by_cohort, window),
                )
                for window in train_windows
            ]
            if len(vectors) < int(_IF_PARAMS["min_train_windows"]):
                continue
            scaled, medians, mads = _scale(vectors)
            model = isolation_forest_cls(
                n_estimators=int(_IF_PARAMS["n_estimators"]),
                max_samples=min(int(_IF_PARAMS["max_samples"]), len(scaled)),
                random_state=int(_IF_PARAMS["random_state"]),
                n_jobs=1,
            )
            model.fit(np.asarray(scaled, dtype=float))
            train_scores = -model.score_samples(np.asarray(scaled, dtype=float))
            quantile = float(_IF_PARAMS["threshold_quantile"])
            threshold = float(np.quantile(train_scores, quantile))
            last_fit = (model, medians, mads, threshold)
            last_fit_day = day_index
            models[day_index] = last_fit

        scored: list[WindowScore] = []
        for window in windows:
            history = _eligible_history(by_endpoint[window.endpoint_id], window.day_index)
            peers = _peer_history(by_cohort, window)
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
                        reason=(
                            "maintenance window suppressed; field session.explicit_upgrade.state."
                        ),
                        model_digest=self._digest,
                        feature_schema_version=FEATURE_SCHEMA_VERSION,
                    )
                )
                continue
            skip = skip_reason(window, history)
            fitted = models.get(window.day_index)
            if skip is not None or fitted is None:
                detail = skip or "insufficient_history"
                scored.append(
                    WindowScore(
                        endpoint_id=window.endpoint_id,
                        day_index=window.day_index,
                        detector=self.name,
                        score=0.0,
                        threshold=Z_THRESHOLD,
                        above_threshold=False,
                        skip_reason=detail,
                        reason=f"{detail}: session_count; field session.uid.",
                        model_digest=self._digest,
                        feature_schema_version=FEATURE_SCHEMA_VERSION,
                    )
                )
                continue
            model, medians, mads, threshold = fitted
            vector = _raw_vector(window, history, peers)
            scaled_row = _apply_scale(vector, medians, mads)
            score = float(-model.score_samples(np.asarray([scaled_row], dtype=float))[0])
            contributions = _contributions(window, history, peers)
            reason = build_reason(contributions, prefix="Isolation Forest multivariate isolation;")
            scored.append(
                WindowScore(
                    endpoint_id=window.endpoint_id,
                    day_index=window.day_index,
                    detector=self.name,
                    score=score,
                    threshold=float(threshold),
                    above_threshold=score >= float(threshold),
                    contributions=list(contributions),
                    reason=reason,
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
