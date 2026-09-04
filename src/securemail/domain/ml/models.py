"""Advisory feature schema, scored windows, and canonical `AnomalyResult` records."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

FEATURE_SCHEMA_VERSION: str = "securemail.advisory_features/v1"

NUMERIC_FEATURE_NAMES: tuple[str, ...] = (
    "tls13_share",
    "tls12_share",
    "tls10_share",
    "handshake_failure_rate",
    "alert_rate",
    "starttls_success_rate",
    "starttls_fallback_rate",
    "forward_secrecy_present_rate",
    "certificate_churn_rate",
    "incomplete_reconstruction_rate",
    "not_observable_rate",
)

MAD_FEATURE_NAMES: tuple[str, ...] = (
    "tls13_share",
    "tls12_share",
    "tls10_share",
    "handshake_failure_rate",
    "alert_rate",
    "starttls_success_rate",
    "starttls_fallback_rate",
    "forward_secrecy_present_rate",
)

CATEGORICAL_FEATURE_NAMES: tuple[str, ...] = (
    "dominant_tls_version",
    "issuer_id",
    "protocol_role",
)

# Reasons must cite one of these canonical evidence paths, never a generic phrase.
EVIDENCE_FIELD_FOR_FEATURE: dict[str, str] = {
    "tls13_share": "handshake.version.selected",
    "tls12_share": "handshake.version.selected",
    "tls10_share": "handshake.version.selected",
    "dominant_tls_version": "handshake.version.selected",
    "handshake_failure_rate": "handshake.established",
    "alert_rate": "handshake.last_alert",
    "starttls_success_rate": "session.explicit_upgrade.state",
    "starttls_fallback_rate": "session.explicit_upgrade.state",
    "forward_secrecy_present_rate": "handshake.key_exchange.mechanism",
    "certificate_churn_rate": "certificate.issuer",
    "issuer_id": "certificate.issuer",
    "incomplete_reconstruction_rate": "flow.reconstruction_quality",
    "not_observable_rate": "handshake.server_certificate_state",
    "protocol_role": "session.protocol",
    "session_count": "session.uid",
}

FEATURE_GROUPS: dict[str, tuple[str, ...]] = {
    "tls_version": ("tls13_share", "tls12_share", "tls10_share", "dominant_tls_version"),
    "handshake_failure": ("handshake_failure_rate",),
    "alerts": ("alert_rate",),
    "starttls": ("starttls_success_rate", "starttls_fallback_rate"),
    "forward_secrecy": ("forward_secrecy_present_rate",),
    "certificate": ("certificate_churn_rate", "issuer_id"),
    "capture_quality": ("incomplete_reconstruction_rate", "not_observable_rate"),
}

KNOWN_EVIDENCE_FIELDS: frozenset[str] = frozenset(EVIDENCE_FIELD_FOR_FEATURE.values())


class ProtocolRole(StrEnum):
    """Cohort key. Derived from well-known port as a hint, never as protocol proof."""

    SMTP_MX = "smtp_mx"
    SMTP_SUBMISSION = "smtp_submission"
    IMAP_ACCESS = "imap_access"
    POP3_ACCESS = "pop3_access"


class AnomalyKind(StrEnum):
    UNIVARIATE = "univariate"
    MULTIVARIATE = "multivariate"


class EndpointWindow(BaseModel):
    """One endpoint × one daily cohort window. No raw identities as model features."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint_id: str = Field(min_length=1, max_length=160)
    site_id: str = Field(min_length=1, max_length=64)
    protocol_role: ProtocolRole
    day_index: int = Field(ge=0)
    session_count: int = Field(ge=0)
    tls13_share: float = Field(ge=0.0, le=1.0)
    tls12_share: float = Field(ge=0.0, le=1.0)
    tls10_share: float = Field(ge=0.0, le=1.0)
    handshake_failure_rate: float = Field(ge=0.0, le=1.0)
    alert_rate: float = Field(ge=0.0, le=1.0)
    starttls_success_rate: float = Field(ge=0.0, le=1.0)
    starttls_fallback_rate: float = Field(ge=0.0, le=1.0)
    forward_secrecy_present_rate: float = Field(ge=0.0, le=1.0)
    certificate_churn_rate: float = Field(ge=0.0, le=1.0)
    incomplete_reconstruction_rate: float = Field(ge=0.0, le=1.0)
    not_observable_rate: float = Field(ge=0.0, le=1.0)
    dominant_tls_version: str = Field(min_length=1, max_length=32)
    issuer_id: str = Field(min_length=1, max_length=64)
    in_maintenance: bool = False
    is_new_endpoint: bool = False
    capture_quality_ok: bool = True


class FeatureContribution(BaseModel):
    """One cited feature used to build an evidence-linked reason string."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    feature: str = Field(min_length=1, max_length=80)
    evidence_field: str = Field(min_length=1, max_length=160)
    value: float | str
    reference: float | str | None = None
    score: float


class WindowScore(BaseModel):
    """Detector output for one endpoint-window. Higher `score` is more anomalous."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint_id: str = Field(min_length=1, max_length=160)
    day_index: int = Field(ge=0)
    detector: str = Field(min_length=1, max_length=64)
    score: float
    threshold: float
    above_threshold: bool
    suppressed: bool = False
    skip_reason: str | None = Field(default=None, max_length=160)
    percentile: float | None = Field(default=None, ge=0.0, le=100.0)
    contributions: list[FeatureContribution] = Field(default_factory=list, max_length=8)
    reason: str = Field(min_length=1, max_length=1000)
    model_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    feature_schema_version: str = Field(min_length=1, max_length=64)


class AnomalyResult(BaseModel):
    """Canonical advisory record. Never merged into `Finding`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    anomaly_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    code: str = Field(min_length=1, max_length=64)
    label: str = Field(min_length=1, max_length=160)
    detector: str = Field(min_length=1, max_length=64)
    score: float
    threshold: float
    percentile: float | None = Field(default=None, ge=0.0, le=100.0)
    cohort: str = Field(min_length=1, max_length=160)
    feature_schema_version: str = Field(min_length=1, max_length=64)
    model_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    endpoint_id: str = Field(min_length=1, max_length=160)
    day_index: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=1000)
    reason_codes: list[str] = Field(default_factory=list, max_length=8)
    evidence_fields: list[str] = Field(default_factory=list, max_length=8)


class SeededEvent(BaseModel):
    """Ground-truth episode injected into a synthetic cohort."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(min_length=1, max_length=80)
    family: str = Field(min_length=1, max_length=64)
    kind: AnomalyKind
    endpoint_id: str = Field(min_length=1, max_length=160)
    start_day: int = Field(ge=0)
    end_day: int = Field(ge=0)


class MaintenanceWindow(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint_id: str = Field(min_length=1, max_length=160)
    start_day: int = Field(ge=0)
    end_day: int = Field(ge=0)


class CohortLabels(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    events: list[SeededEvent] = Field(default_factory=list, max_length=64)
    maintenance: list[MaintenanceWindow] = Field(default_factory=list, max_length=32)
    jitter_endpoints: list[str] = Field(default_factory=list, max_length=32)
    new_endpoints: list[str] = Field(default_factory=list, max_length=16)


class CohortManifest(BaseModel):
    """Frozen evaluation contract for one seeded cohort."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cohort_id: str = Field(min_length=1, max_length=80)
    seed: int
    feature_schema_version: str = Field(min_length=1, max_length=64)
    n_days: int = Field(ge=1)
    warmup_days: int = Field(ge=1)
    min_history_windows: int = Field(ge=1)
    detection_delay_windows: int = Field(ge=0)
    top_k: int = Field(ge=1)
    baseline_precision_floor: float = Field(ge=0.0, le=1.0)
    isolation_forest_precision_lift: float = Field(ge=0.0, le=1.0)
    justification: str = Field(min_length=1, max_length=2000)


class DetectorEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    detector: str = Field(min_length=1, max_length=64)
    model_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    precision_at_k: float = Field(ge=0.0, le=1.0)
    k: int = Field(ge=1)
    detection_delays: dict[str, int | None] = Field(default_factory=dict)
    median_delay: float | None = None
    p90_delay: float | None = None
    alerts_per_1000_endpoint_days: float = Field(ge=0.0)
    clean_alert_rate: float = Field(ge=0.0)
    maintenance_alert_rate: float = Field(ge=0.0)
    new_endpoint_alert_count: int = Field(ge=0)
    ranked_endpoint_ids: list[str] = Field(default_factory=list, max_length=64)


class GateResults(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    baseline_precision_floor: bool
    baseline_beats_null: bool
    detection_delay: bool
    challenger_precision_lift: bool
    lift_ci_excludes_zero: bool
    median_delay_no_worse: bool
    p90_delay_within_slack: bool
    alert_rate_regression: bool

    @property
    def all_passed(self) -> bool:
        return all(
            (
                self.baseline_precision_floor,
                self.baseline_beats_null,
                self.detection_delay,
                self.challenger_precision_lift,
                self.lift_ci_excludes_zero,
                self.median_delay_no_worse,
                self.p90_delay_within_slack,
                self.alert_rate_regression,
            )
        )


class EvaluationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    cohort_id: str = Field(min_length=1, max_length=80)
    feature_schema_version: str = Field(min_length=1, max_length=64)
    null_detector: DetectorEvaluation
    baseline: DetectorEvaluation
    challenger: DetectorEvaluation | None = None
    precision_lift: float | None = None
    lift_ci_low: float | None = None
    lift_ci_high: float | None = None
    gates: GateResults


def numeric_value(window: EndpointWindow, name: str) -> float:
    """Read a declared numeric feature from an endpoint window."""

    if name not in NUMERIC_FEATURE_NAMES:
        raise KeyError(name)
    value = getattr(window, name)
    if not isinstance(value, float):
        return float(value)
    return value


def categorical_value(window: EndpointWindow, name: str) -> str:
    """Read a declared categorical feature from an endpoint window."""

    if name not in CATEGORICAL_FEATURE_NAMES:
        raise KeyError(name)
    value = getattr(window, name)
    if isinstance(value, ProtocolRole):
        return value.value
    return str(value)
