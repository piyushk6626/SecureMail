"""Seeded multi-week endpoint-cohort generator for Step 10 evaluation."""

from __future__ import annotations

import json
from pathlib import Path
from random import Random

from securemail.domain.ml.evaluation import (
    BASELINE_PRECISION_FLOOR,
    DETECTION_DELAY_WINDOWS,
    ISOLATION_FOREST_PRECISION_LIFT,
    MIN_HISTORY_WINDOWS,
    TOP_K,
    WARMUP_DAYS,
)
from securemail.domain.ml.models import (
    FEATURE_SCHEMA_VERSION,
    AnomalyKind,
    CohortLabels,
    CohortManifest,
    EndpointWindow,
    MaintenanceWindow,
    ProtocolRole,
    SeededEvent,
)

LOCKED_EVAL_SEED = 20260904
DEV_SEED = 20260101
COHORT_ID = "cohort_seeded_v1"
N_DAYS = 70

_JUSTIFICATION = (
    "Daily windows match the cohort grain. Detection within 2 windows is one missed "
    "daily job plus the next. Top-5 is a small analyst budget. A 0.60 baseline floor "
    "is 3/5 true endpoints in that budget. A +0.10 Isolation Forest lift is a material "
    "effect on multivariate templates the per-endpoint MAD/rarity baseline is designed "
    "to miss. Development seed 20260101 is held out; locked evaluation uses 20260904."
)


class _Spec:
    def __init__(
        self,
        endpoint_id: str,
        site_id: str,
        role: ProtocolRole,
        issuer_id: str,
        tls13: float,
        tls12: float,
        failure: float,
        fallback: float,
        fs: float,
        spread: float,
        first_day: int = 0,
        is_new: bool = False,
    ) -> None:
        self.endpoint_id = endpoint_id
        self.site_id = site_id
        self.role = role
        self.issuer_id = issuer_id
        self.tls13 = tls13
        self.tls12 = tls12
        self.failure = failure
        self.fallback = fallback
        self.fs = fs
        self.spread = spread
        self.first_day = first_day
        self.is_new = is_new


def _clip01(value: float) -> float:
    return max(0.0, min(1.0, value))


def _shares(tls13: float, tls12: float, tls10: float) -> tuple[float, float, float]:
    total = tls13 + tls12 + tls10
    if total <= 0:
        return 1.0, 0.0, 0.0
    return tls13 / total, tls12 / total, tls10 / total


def _dominant(tls13: float, tls12: float, tls10: float) -> str:
    if tls10 >= tls13 and tls10 >= tls12:
        return "TLSv10"
    if tls12 > tls13:
        return "TLSv12"
    return "TLSv13"


def _specs() -> list[_Spec]:
    mx = ProtocolRole.SMTP_MX
    sub = ProtocolRole.SMTP_SUBMISSION
    imap = ProtocolRole.IMAP_ACCESS
    pop3 = ProtocolRole.POP3_ACCESS
    return [
        _Spec("mx-01", "site_a", mx, "iss_mx_a", 0.96, 0.04, 0.002, 0.008, 0.99, 0.006),
        _Spec("mx-02", "site_a", mx, "iss_mx_a", 0.96, 0.04, 0.002, 0.008, 0.99, 0.006),
        _Spec("mx-03", "site_a", mx, "iss_mx_a", 0.96, 0.04, 0.002, 0.008, 0.99, 0.006),
        _Spec("mx-04", "site_a", mx, "iss_mx_a", 0.95, 0.05, 0.002, 0.010, 0.99, 0.007),
        _Spec("mx-05", "site_a", mx, "iss_mx_b", 0.94, 0.06, 0.003, 0.010, 0.98, 0.007),
        _Spec("mx-b1", "site_b", mx, "iss_mx_b", 0.95, 0.05, 0.002, 0.009, 0.99, 0.006),
        _Spec("mx-b2", "site_b", mx, "iss_mx_b", 0.93, 0.07, 0.003, 0.011, 0.98, 0.008),
        _Spec("sub-01", "site_a", sub, "iss_sub", 0.70, 0.30, 0.004, 0.020, 0.97, 0.012),
        _Spec("sub-02", "site_a", sub, "iss_sub", 0.68, 0.32, 0.005, 0.018, 0.96, 0.012),
        _Spec("sub-03", "site_b", sub, "iss_sub", 0.72, 0.28, 0.004, 0.016, 0.97, 0.012),
        _Spec("sub-04", "site_b", sub, "iss_sub", 0.66, 0.34, 0.006, 0.022, 0.95, 0.012),
        _Spec("imap-01", "site_a", imap, "iss_imap", 0.90, 0.10, 0.008, 0.012, 0.97, 0.018),
        _Spec("imap-02", "site_a", imap, "iss_imap_peer", 0.88, 0.12, 0.010, 0.014, 0.96, 0.020),
        _Spec("imap-03", "site_b", imap, "iss_imap", 0.91, 0.09, 0.007, 0.011, 0.97, 0.016),
        _Spec("imap-04", "site_b", imap, "iss_imap_peer", 0.87, 0.13, 0.011, 0.015, 0.95, 0.021),
        _Spec("pop-01", "site_a", pop3, "iss_pop", 0.82, 0.18, 0.016, 0.010, 0.94, 0.014),
        _Spec("pop-02", "site_a", pop3, "iss_pop_peer", 0.80, 0.20, 0.018, 0.012, 0.93, 0.015),
        _Spec("pop-03", "site_b", pop3, "iss_pop", 0.84, 0.16, 0.015, 0.009, 0.95, 0.013),
        _Spec("mx-07", "site_b", mx, "iss_mx_b", 0.96, 0.04, 0.002, 0.008, 0.99, 0.005),
        _Spec("mx-noise-1", "site_a", mx, "iss_mx_a", 0.96, 0.04, 0.002, 0.008, 0.99, 0.005),
        _Spec("mx-noise-2", "site_a", mx, "iss_mx_a", 0.96, 0.04, 0.002, 0.008, 0.99, 0.005),
        _Spec("mx-noise-3", "site_b", mx, "iss_mx_b", 0.95, 0.05, 0.002, 0.009, 0.99, 0.005),
        _Spec(
            "imap-new",
            "site_a",
            imap,
            "iss_imap",
            0.90,
            0.10,
            0.008,
            0.012,
            0.97,
            0.018,
            first_day=50,
            is_new=True,
        ),
        _Spec("mx-06", "site_a", mx, "iss_mx_a", 0.97, 0.03, 0.002, 0.007, 0.99, 0.005),
    ]


def _base_window(rng: Random, spec: _Spec, day_index: int) -> EndpointWindow:
    tls10 = _clip01(abs(rng.gauss(0.0, 0.0008)))
    tls13 = _clip01(spec.tls13 + rng.gauss(0.0, spec.spread))
    tls12 = _clip01(spec.tls12 + rng.gauss(0.0, spec.spread))
    tls13, tls12, tls10 = _shares(tls13, tls12, tls10)
    failure = _clip01(spec.failure + rng.gauss(0.0, spec.spread * 0.4))
    alert = _clip01(0.002 + rng.gauss(0.0, spec.spread * 0.3))
    fallback = _clip01(spec.fallback + rng.gauss(0.0, spec.spread * 0.4))
    success = _clip01(1.0 - fallback - abs(rng.gauss(0.0, 0.01)))
    fs = _clip01(spec.fs + rng.gauss(0.0, spec.spread * 0.2))
    incomplete = _clip01(0.02 + abs(rng.gauss(0.0, 0.01)))
    not_obs = _clip01(0.01 + abs(rng.gauss(0.0, 0.008)))
    sessions = 70 + rng.randint(0, 50)
    return EndpointWindow(
        endpoint_id=spec.endpoint_id,
        site_id=spec.site_id,
        protocol_role=spec.role,
        day_index=day_index,
        session_count=sessions,
        tls13_share=tls13,
        tls12_share=tls12,
        tls10_share=tls10,
        handshake_failure_rate=failure,
        alert_rate=alert,
        starttls_success_rate=success,
        starttls_fallback_rate=fallback,
        forward_secrecy_present_rate=fs,
        certificate_churn_rate=0.0,
        incomplete_reconstruction_rate=incomplete,
        not_observable_rate=not_obs,
        dominant_tls_version=_dominant(tls13, tls12, tls10),
        issuer_id=spec.issuer_id,
        in_maintenance=False,
        is_new_endpoint=spec.is_new and (day_index - spec.first_day) < MIN_HISTORY_WINDOWS,
        capture_quality_ok=incomplete <= 0.35,
    )


def _replace(window: EndpointWindow, **changes: object) -> EndpointWindow:
    payload = window.model_dump()
    payload.update(changes)
    tls13 = float(payload["tls13_share"])
    tls12 = float(payload["tls12_share"])
    tls10 = float(payload["tls10_share"])
    tls13, tls12, tls10 = _shares(tls13, tls12, tls10)
    payload["tls13_share"] = tls13
    payload["tls12_share"] = tls12
    payload["tls10_share"] = tls10
    payload["dominant_tls_version"] = _dominant(tls13, tls12, tls10)
    return EndpointWindow.model_validate(payload)


def _apply_overlays(windows: list[EndpointWindow]) -> list[EndpointWindow]:
    by_key = {(item.endpoint_id, item.day_index): item for item in windows}

    def overlay(endpoint_id: str, start: int, end: int, **changes: object) -> None:
        for day in range(start, end + 1):
            current = by_key[(endpoint_id, day)]
            by_key[(endpoint_id, day)] = _replace(current, **changes)

    overlay(
        "mx-01",
        40,
        46,
        tls13_share=0.03,
        tls12_share=0.02,
        tls10_share=0.95,
        handshake_failure_rate=0.003,
    )
    overlay(
        "mx-02",
        45,
        51,
        handshake_failure_rate=0.18,
        alert_rate=0.12,
    )
    overlay(
        "sub-01",
        48,
        54,
        starttls_fallback_rate=0.42,
        starttls_success_rate=0.50,
    )
    overlay(
        "imap-01",
        50,
        56,
        tls10_share=0.040,
        tls13_share=0.87,
        tls12_share=0.090,
        handshake_failure_rate=0.016,
        forward_secrecy_present_rate=0.955,
        issuer_id="iss_imap_peer",
        certificate_churn_rate=0.12,
    )
    overlay(
        "pop-01",
        38,
        44,
        tls10_share=0.042,
        tls13_share=0.78,
        tls12_share=0.178,
        handshake_failure_rate=0.022,
        starttls_fallback_rate=0.022,
        issuer_id="iss_novel_pop",
        certificate_churn_rate=0.10,
    )
    overlay(
        "mx-03",
        36,
        38,
        tls13_share=0.70,
        tls12_share=0.30,
        tls10_share=0.0,
        in_maintenance=True,
    )
    jitter: dict[str, tuple[int, ...]] = {
        "mx-noise-1": (33, 41, 55),
        "mx-noise-2": (34, 47, 58),
        "mx-noise-3": (31, 49, 61),
    }
    for endpoint_id, days in jitter.items():
        for day in days:
            current = by_key[(endpoint_id, day)]
            by_key[(endpoint_id, day)] = _replace(
                current,
                tls12_share=0.11,
                tls13_share=0.89,
                tls10_share=0.0,
            )
    return [by_key[key] for key in sorted(by_key)]


def locked_labels() -> CohortLabels:
    return CohortLabels(
        events=[
            SeededEvent(
                event_id="tls_downgrade_mx01",
                family="tls_downgrade",
                kind=AnomalyKind.UNIVARIATE,
                endpoint_id="mx-01",
                start_day=40,
                end_day=46,
            ),
            SeededEvent(
                event_id="failure_spike_mx02",
                family="failure_spike",
                kind=AnomalyKind.UNIVARIATE,
                endpoint_id="mx-02",
                start_day=45,
                end_day=51,
            ),
            SeededEvent(
                event_id="starttls_fallback_sub01",
                family="starttls_fallback",
                kind=AnomalyKind.UNIVARIATE,
                endpoint_id="sub-01",
                start_day=48,
                end_day=54,
            ),
            SeededEvent(
                event_id="subtle_combo_imap01",
                family="subtle_combo",
                kind=AnomalyKind.MULTIVARIATE,
                endpoint_id="imap-01",
                start_day=50,
                end_day=56,
            ),
            SeededEvent(
                event_id="subtle_issuer_failure_pop01",
                family="subtle_combo",
                kind=AnomalyKind.MULTIVARIATE,
                endpoint_id="pop-01",
                start_day=38,
                end_day=44,
            ),
        ],
        maintenance=[MaintenanceWindow(endpoint_id="mx-03", start_day=36, end_day=38)],
        jitter_endpoints=["mx-noise-1", "mx-noise-2", "mx-noise-3"],
        new_endpoints=["imap-new"],
    )


def locked_manifest() -> CohortManifest:
    return CohortManifest(
        cohort_id=COHORT_ID,
        seed=LOCKED_EVAL_SEED,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        n_days=N_DAYS,
        warmup_days=WARMUP_DAYS,
        min_history_windows=MIN_HISTORY_WINDOWS,
        detection_delay_windows=DETECTION_DELAY_WINDOWS,
        top_k=TOP_K,
        baseline_precision_floor=BASELINE_PRECISION_FLOOR,
        isolation_forest_precision_lift=ISOLATION_FOREST_PRECISION_LIFT,
        justification=_JUSTIFICATION,
    )


def generate_cohort(*, seed: int = LOCKED_EVAL_SEED, n_days: int = N_DAYS) -> list[EndpointWindow]:
    rng = Random(seed)
    windows: list[EndpointWindow] = []
    for spec in _specs():
        for day in range(n_days):
            if day < spec.first_day:
                continue
            windows.append(_base_window(rng, spec, day))
    return _apply_overlays(windows)


def generate_locked_cohort() -> tuple[list[EndpointWindow], CohortLabels, CohortManifest]:
    return generate_cohort(seed=LOCKED_EVAL_SEED), locked_labels(), locked_manifest()


def cohort_payload(
    windows: list[EndpointWindow],
    labels: CohortLabels,
    manifest: CohortManifest,
) -> dict[str, object]:
    return {
        "manifest": manifest.model_dump(mode="json"),
        "labels": labels.model_dump(mode="json"),
        "windows": [item.model_dump(mode="json") for item in windows],
    }


def write_cohort_dir(
    path: Path,
    *,
    windows: list[EndpointWindow],
    labels: CohortLabels,
    manifest: CohortManifest,
) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "manifest.json").write_text(
        json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (path / "labels.json").write_text(
        json.dumps(labels.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (path / "windows.json").write_text(
        json.dumps([item.model_dump(mode="json") for item in windows], indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )


def load_cohort_dir(path: Path) -> tuple[list[EndpointWindow], CohortLabels, CohortManifest]:
    manifest = CohortManifest.model_validate_json(
        (path / "manifest.json").read_text(encoding="utf-8")
    )
    labels = CohortLabels.model_validate_json((path / "labels.json").read_text(encoding="utf-8"))
    raw = json.loads((path / "windows.json").read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("windows.json must be a list")
    windows = [EndpointWindow.model_validate(item) for item in raw]
    return windows, labels, manifest


def default_cohort_dir() -> Path:
    return Path(__file__).resolve().parent / COHORT_ID
