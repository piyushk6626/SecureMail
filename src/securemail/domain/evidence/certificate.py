"""Canonical per-certificate facts (v1 envelope, Steps 5–6). Path and identity are nested."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from securemail.domain.evidence.run import EvidenceState

MAX_CERTIFICATE_DER_BYTES = 65_536
MAX_CERTIFICATES_PER_RUN = 256
MAX_ASN1_DEPTH = 16
MAX_CHAIN_DEPTH = 16


class CertificateRole(StrEnum):
    """Whether the certificate was offered by the TLS server or the client."""

    SERVER = "server"
    CLIENT = "client"


class RevocationStatus(StrEnum):
    """Revocation outcome. Without imported OCSP/CRL evidence this is unknown."""

    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    STALE = "stale"


class ReferenceIdentitySource(StrEnum):
    """Where the hostname/IP used for identity matching came from."""

    SNI = "sni"
    CONFIGURED = "configured"


class CertificateValidation(BaseModel):
    """Independent chain and identity outcomes. Attached to server leaves only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    certificate_observed: bool
    syntax_valid: bool | None = None
    path_valid_at_capture_time: bool | None = None
    path_valid_at_analysis_time: bool | None = None
    path_invalid_reasons_at_capture_time: list[str] = Field(default_factory=list, max_length=8)
    path_invalid_reasons_at_analysis_time: list[str] = Field(default_factory=list, max_length=8)
    identity_match: bool | None = None
    identity_mismatch_reasons: list[str] = Field(default_factory=list, max_length=8)
    reference_identity: str | None = None
    reference_identity_source: ReferenceIdentitySource | None = None
    revocation_status: RevocationStatus
    trust_profile_id: str
    trust_store_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    indeterminate_reasons: list[str] = Field(default_factory=list, max_length=8)


class CertificateEvidence(BaseModel):
    """One extracted X.509 certificate. Path/identity live on `validation` for leaves."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    der_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    uid: str
    chain_index: int = Field(ge=0)
    role: CertificateRole
    source_frames: list[int] = Field(default_factory=list)
    syntax_valid: bool
    syntax_error: str | None = None
    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    valid_at_capture_time: bool | None = None
    valid_at_analysis_time: bool | None = None
    expires_within_warning_window: bool | None = None
    public_key_algorithm: str | None = None
    public_key_size: int | None = None
    public_key_curve: str | None = None
    effective_strength_bits: int | None = None
    signature_algorithm: str | None = None
    evidence_state: EvidenceState
    validation: CertificateValidation | None = None

    @field_serializer("not_before", "not_after")
    def _serialize_datetime(self, value: datetime | None) -> str | None:
        if value is None:
            return None
        aware = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return aware.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rebuild_evidence_document() -> None:
    """Resolve `CertificateEvidence` on `EvidenceDocument` without an import cycle."""

    from securemail.domain.evidence.flow import Flow
    from securemail.domain.evidence.handshake import TlsHandshake
    from securemail.domain.evidence.run import EvidenceDocument
    from securemail.domain.evidence.session import EmailSession
    from securemail.domain.findings.finding import Finding
    from securemail.domain.findings.posture import PolicyCheck, PostureAssessment

    EvidenceDocument.model_rebuild(
        _types_namespace={
            "Flow": Flow,
            "EmailSession": EmailSession,
            "TlsHandshake": TlsHandshake,
            "CertificateEvidence": CertificateEvidence,
            "Finding": Finding,
            "PolicyCheck": PolicyCheck,
            "PostureAssessment": PostureAssessment,
        }
    )


_rebuild_evidence_document()
