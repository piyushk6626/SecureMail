"""Canonical `Finding` records produced by the Step 7 policy engine."""

from __future__ import annotations

from datetime import UTC, date, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from securemail.domain.evidence.run import EvidenceState


class FindingOutcome(StrEnum):
    """Serialized policy outcomes. Pass/present results are not emitted as findings."""

    NEGATIVE = "negative"
    INDETERMINATE = "indeterminate"


class FindingSeverity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class EvidenceRecordType(StrEnum):
    FLOW = "flow"
    SESSION = "session"
    HANDSHAKE = "handshake"
    CERTIFICATE = "certificate"


class EvidenceReference(BaseModel):
    """Canonical pointer at a contributing evidence field. No JSON array indexes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record_type: EvidenceRecordType
    record_key: str = Field(min_length=1, max_length=160)
    field_path: str = Field(min_length=1, max_length=160)
    evidence_state: EvidenceState
    frame_number: int | None = Field(default=None, ge=1)


class Finding(BaseModel):
    """Deterministic policy judgment. Never mutates the underlying evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    code: str = Field(min_length=1, max_length=64)
    outcome: FindingOutcome
    title: str = Field(min_length=1, max_length=160)
    rationale: str = Field(min_length=1, max_length=1000)
    standards: list[str] = Field(default_factory=list, max_length=8)
    remediation_id: str = Field(min_length=1, max_length=64)
    severity: FindingSeverity
    evaluation_state: EvidenceState
    basis_state: EvidenceState
    policy_profile: str = Field(min_length=1, max_length=64)
    policy_pack_version: str = Field(pattern=r"^[0-9a-f]{64}$")
    rule_effective_from: date
    rule_effective_until: date | None = None
    policy_evaluation_time: datetime
    affected_endpoint: str = Field(min_length=1, max_length=300)
    evidence_references: list[EvidenceReference] = Field(default_factory=list, max_length=32)

    @field_serializer("rule_effective_from", "rule_effective_until")
    def _serialize_date(self, value: date | None) -> str | None:
        if value is None:
            return None
        return value.isoformat()

    @field_serializer("policy_evaluation_time")
    def _serialize_datetime(self, value: datetime) -> str:
        aware = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return aware.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rebuild_evidence_document() -> None:
    from securemail.domain.evidence.certificate import CertificateEvidence
    from securemail.domain.evidence.flow import Flow
    from securemail.domain.evidence.handshake import TlsHandshake
    from securemail.domain.evidence.run import EvidenceDocument
    from securemail.domain.evidence.session import EmailSession
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
