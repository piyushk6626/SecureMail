"""Canonical run identity and the shared evidence-state vocabulary (schema v0)."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from securemail.domain.evidence.certificate import CertificateEvidence
    from securemail.domain.evidence.flow import Flow
    from securemail.domain.evidence.handshake import TlsHandshake
    from securemail.domain.evidence.session import EmailSession

NORMALIZATION_SCHEMA_VERSION: Literal["v0"] = "v0"


class EvidenceState(StrEnum):
    """Mandatory visibility/confidence state for every applicable evidence field."""

    OBSERVED = "observed"
    VERIFIED = "verified"
    INFERRED = "inferred"
    INCOMPLETE = "incomplete"
    CONFLICTING = "conflicting"
    NOT_OBSERVABLE = "not_observable"
    INDETERMINATE = "indeterminate"


class AnalysisRun(BaseModel):
    """Identity record for one analysis of one capture."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    analyzer_bundle_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalization_schema_version: Literal["v0"]
    configuration_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_pack_version: str | None = None
    trust_store_digest: str | None = None


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


class EvidenceDocument(BaseModel):
    """v0 canonical JSON envelope produced by `securemail analyze`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v0"] = "v0"
    run_identity: AnalysisRun
    capture_preflight: CapturePreflight
    flows: list[Flow] = Field(default_factory=list)
    sessions: list[EmailSession] = Field(default_factory=list)
    handshakes: list[TlsHandshake] = Field(default_factory=list)
    certificates: list[CertificateEvidence] = Field(default_factory=list)
