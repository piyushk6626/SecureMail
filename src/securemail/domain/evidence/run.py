"""Canonical run identity and the shared evidence-state vocabulary (schema v1)."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer

if TYPE_CHECKING:
    from securemail.domain.evidence.certificate import CertificateEvidence
    from securemail.domain.evidence.flow import Flow
    from securemail.domain.evidence.handshake import TlsHandshake
    from securemail.domain.evidence.session import EmailSession
    from securemail.domain.findings.finding import Finding
    from securemail.domain.findings.posture import PolicyCheck, PostureAssessment

NORMALIZATION_SCHEMA_VERSION: Literal["v1"] = "v1"
EVIDENCE_DOCUMENT_SCHEMA_VERSION: Literal["v2"] = "v2"


class EvidenceState(StrEnum):
    """Mandatory visibility/confidence state for every applicable evidence field."""

    OBSERVED = "observed"
    VERIFIED = "verified"
    INFERRED = "inferred"
    INCOMPLETE = "incomplete"
    CONFLICTING = "conflicting"
    NOT_OBSERVABLE = "not_observable"
    INDETERMINATE = "indeterminate"


class PolicyProfile(StrEnum):
    """Built-in Step 7 policy packs. Organization packs are deferred."""

    IETF_CURRENT = "ietf_current"
    NIST_FEDERAL = "nist_federal"
    HISTORICAL_AT_CAPTURE = "historical_at_capture"


class AnalysisRun(BaseModel):
    """Identity record for one analysis of one capture."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    analyzer_bundle_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalization_schema_version: Literal["v1"]
    configuration_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    analysis_time: datetime
    policy_profile: PolicyProfile
    policy_pack_version: str = Field(pattern=r"^[0-9a-f]{64}$")
    trust_store_digest: str | None = None

    @field_serializer("analysis_time")
    def _serialize_analysis_time(self, value: datetime) -> str:
        aware = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return aware.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


class CapturePreflight(BaseModel):
    """capinfos facts recorded before any analyzer mutates a working copy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    packet_count: int = Field(ge=0)
    file_time_precision: str
    packet_size_limit: int | None = None
    packet_size_limit_min_inferred: int | None = None
    packet_size_limit_max_inferred: int | None = None
    truncated_packets_present: bool
    original_packet_bytes: int | None = None
    capture_duration_seconds: float | None = None
    capture_start_time: datetime | None = None

    @field_serializer("capture_start_time")
    def _serialize_capture_start(self, value: datetime | None) -> str | None:
        if value is None:
            return None
        aware = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return aware.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


class EvidenceDocument(BaseModel):
    """v2 canonical JSON envelope produced by `securemail analyze`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v2"] = "v2"
    run_identity: AnalysisRun
    capture_preflight: CapturePreflight
    flows: list[Flow] = Field(default_factory=list)
    sessions: list[EmailSession] = Field(default_factory=list)
    handshakes: list[TlsHandshake] = Field(default_factory=list)
    certificates: list[CertificateEvidence] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    policy_checks: list[PolicyCheck] = Field(default_factory=list, max_length=16384)
    posture: PostureAssessment
