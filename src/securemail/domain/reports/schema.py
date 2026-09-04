"""Versioned canonical report envelope (schema-first Step 9 contract)."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_validator

from securemail.domain.evidence.flow import ReconstructionQuality
from securemail.domain.evidence.run import EvidenceDocument, EvidenceState
from securemail.domain.findings.finding import Finding
from securemail.domain.findings.posture import AssessmentState

REPORT_SCHEMA_VERSION: Literal["securemail.report/v1"] = "securemail.report/v1"
HTML_RENDERER_ID: Literal["securemail.html/v1"] = "securemail.html/v1"
PDF_RENDERER_ID: Literal["weasyprint"] = "weasyprint"
REPORT_TEMPLATE_NAME: Literal["report.html.j2"] = "report.html.j2"

_SHA256 = r"^[0-9a-f]{64}$"


class Availability(StrEnum):
    """Whether a requested provenance field could be populated from evidence."""

    PRESENT = "present"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


class SourceRecordKind(StrEnum):
    CASE = "case"
    CAPTURE = "capture"
    ANALYSIS_RUN = "analysis_run"


class SourceRecord(BaseModel):
    """Identifier for a record the report was assembled from."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: SourceRecordKind
    identifier: str | None = Field(default=None, max_length=160)
    availability: Availability


class ArtifactHash(BaseModel):
    """Named content hash. `sha256` is required only when `availability` is present."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=160)
    sha256: str | None = Field(default=None, pattern=_SHA256)
    availability: Availability

    @model_validator(mode="after")
    def _hash_matches_availability(self) -> ArtifactHash:
        if self.availability is Availability.PRESENT and self.sha256 is None:
            raise ValueError("present artifact hashes require sha256")
        if self.availability is not Availability.PRESENT and self.sha256 is not None:
            raise ValueError("unavailable artifact hashes must not include sha256")
        return self


class FontResource(BaseModel):
    """Pinned bundled font used by HTML and PDF presentation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    filename: str = Field(min_length=1, max_length=160)
    sha256: str = Field(pattern=_SHA256)
    family: str = Field(min_length=1, max_length=80)
    weight: int = Field(ge=100, le=900)
    style: Literal["normal", "italic"] = "normal"


class RendererManifest(BaseModel):
    """How this JSON is turned into HTML/PDF. Upgrade these pins deliberately."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    html_renderer: Literal["securemail.html/v1"] = HTML_RENDERER_ID
    pdf_renderer: Literal["weasyprint"] = PDF_RENDERER_ID
    pdf_renderer_version: str = Field(min_length=1, max_length=32)
    template_name: Literal["report.html.j2"] = REPORT_TEMPLATE_NAME
    template_sha256: str = Field(pattern=_SHA256)
    fonts: list[FontResource] = Field(min_length=1, max_length=16)


class SignatureMetadata(BaseModel):
    """Detached signing/timestamping is out of Step 9; record unavailability."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    availability: Literal["unavailable"] = "unavailable"
    algorithm: str | None = None
    timestamp: datetime | None = None

    @field_serializer("timestamp")
    def _serialize_timestamp(self, value: datetime | None) -> str | None:
        return _rfc3339_z(value)


class PostureSummary(BaseModel):
    """Headline posture copied from `evidence.posture`. Not independently scored."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    assessment_state: AssessmentState
    risk_score: int | None = Field(default=None, ge=0, le=100)
    finding_count: int = Field(ge=0)
    unknown_count: int = Field(ge=0)
    not_observable_count: int = Field(ge=0)


class ReportManifest(BaseModel):
    """Provenance wrapper around one `EvidenceDocument`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["securemail.report/v1"] = REPORT_SCHEMA_VERSION
    generated_at: datetime
    case_id: str | None = Field(default=None, max_length=160)
    capture_id: str | None = Field(default=None, max_length=160)
    analysis_run_id: str | None = Field(default=None, max_length=160)
    source_capture_sha256: str = Field(pattern=_SHA256)
    working_copy_sha256: str | None = Field(default=None, pattern=_SHA256)
    working_copy_availability: Availability
    source_records: list[SourceRecord] = Field(min_length=1, max_length=16)
    artifact_hashes: list[ArtifactHash] = Field(default_factory=list, max_length=32)
    renderer: RendererManifest
    signature: SignatureMetadata
    posture_summary: PostureSummary
    timezone: Literal["UTC"] = "UTC"
    random_seed: str | None = Field(default=None, max_length=64)
    configuration_digest: str = Field(pattern=_SHA256)
    analyzer_bundle_digest: str = Field(pattern=_SHA256)
    policy_profile: str = Field(min_length=1, max_length=64)
    policy_pack_version: str = Field(pattern=_SHA256)
    trust_store_digest: str | None = Field(default=None, pattern=_SHA256)
    os_container: str | None = Field(default=None, max_length=160)
    os_container_availability: Availability
    dependency_versions: dict[str, str] = Field(default_factory=dict, max_length=32)

    @field_serializer("generated_at")
    def _serialize_generated_at(self, value: datetime) -> str:
        serialized = _rfc3339_z(value)
        if serialized is None:
            raise ValueError("generated_at is required")
        return serialized

    @model_validator(mode="after")
    def _working_copy_matches_availability(self) -> ReportManifest:
        present = self.working_copy_availability is Availability.PRESENT
        if present and self.working_copy_sha256 is None:
            raise ValueError("present working-copy hash requires sha256")
        if not present and self.working_copy_sha256 is not None:
            raise ValueError("unavailable working-copy hash must be omitted")
        if self.os_container_availability is Availability.PRESENT and self.os_container is None:
            raise ValueError("present os_container requires a value")
        if (
            self.os_container_availability is not Availability.PRESENT
            and self.os_container is not None
        ):
            raise ValueError("unavailable os_container must be omitted")
        return self


class CaptureLimitations(BaseModel):
    """Visibility and reconstruction limits that must not be read as a pass."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    truncated_packets_present: bool
    incomplete_flow_count: int = Field(ge=0)
    conflicting_flow_count: int = Field(ge=0)
    not_observable_certificate_count: int = Field(ge=0)
    unknown_check_count: int = Field(ge=0)
    not_observable_check_count: int = Field(ge=0)
    notes: list[str] = Field(default_factory=list, max_length=32)


class StageError(BaseModel):
    """Inspectable stage failure. Empty when the analysis completed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stage: str = Field(min_length=1, max_length=80)
    message: str = Field(min_length=1, max_length=1000)
    evidence_state: EvidenceState


class AdvisoryItem(BaseModel):
    """ML advisory placeholder. Step 10 fills this; Step 9 keeps it empty."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=1000)


class AdvisorySection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    present: bool = False
    items: list[AdvisoryItem] = Field(default_factory=list, max_length=256)

    @model_validator(mode="after")
    def _empty_when_absent(self) -> AdvisorySection:
        if not self.present and self.items:
            raise ValueError("advisory items require present=true")
        if self.present and not self.items:
            raise ValueError("present advisory section requires items")
        return self


class AnalystSection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    present: bool = False
    notes: list[str] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def _empty_when_absent(self) -> AnalystSection:
        if not self.present and self.notes:
            raise ValueError("analyst notes require present=true")
        if self.present and not self.notes:
            raise ValueError("present analyst section requires notes")
        return self


class CanonicalReport(BaseModel):
    """Authoritative report object. HTML and PDF are presentations of this model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["securemail.report/v1"] = REPORT_SCHEMA_VERSION
    manifest: ReportManifest
    evidence: EvidenceDocument
    limitations: CaptureLimitations
    stage_errors: list[StageError] = Field(default_factory=list, max_length=256)
    suppressed_findings: list[Finding] = Field(default_factory=list, max_length=256)
    exceptions: list[str] = Field(default_factory=list, max_length=64)
    advisory: AdvisorySection = Field(default_factory=AdvisorySection)
    analyst_conclusions: AnalystSection = Field(default_factory=AnalystSection)

    @model_validator(mode="after")
    def _manifest_tracks_evidence(self) -> CanonicalReport:
        run = self.evidence.run_identity
        manifest = self.manifest
        if manifest.source_capture_sha256 != run.capture_sha256:
            raise ValueError("manifest.source_capture_sha256 must match run identity")
        if manifest.configuration_digest != run.configuration_digest:
            raise ValueError("manifest.configuration_digest must match run identity")
        if manifest.analyzer_bundle_digest != run.analyzer_bundle_digest:
            raise ValueError("manifest.analyzer_bundle_digest must match run identity")
        if manifest.policy_profile != run.policy_profile.value:
            raise ValueError("manifest.policy_profile must match run identity")
        if manifest.policy_pack_version != run.policy_pack_version:
            raise ValueError("manifest.policy_pack_version must match run identity")
        if manifest.trust_store_digest != run.trust_store_digest:
            raise ValueError("manifest.trust_store_digest must match run identity")
        posture = self.evidence.posture
        summary = manifest.posture_summary
        if summary.assessment_state != posture.assessment_state:
            raise ValueError("posture_summary.assessment_state must match evidence")
        if summary.risk_score != posture.risk_score:
            raise ValueError("posture_summary.risk_score must match evidence")
        if summary.finding_count != len(posture.prioritized_findings):
            raise ValueError("posture_summary.finding_count must match prioritized findings")
        overall = posture.coverage.overall
        if summary.unknown_count != overall.unknown_count:
            raise ValueError("posture_summary.unknown_count must match coverage")
        if summary.not_observable_count != overall.not_observable_count:
            raise ValueError("posture_summary.not_observable_count must match coverage")
        limitations = self.limitations
        if limitations.truncated_packets_present != (
            self.evidence.capture_preflight.truncated_packets_present
        ):
            raise ValueError("limitations.truncated_packets_present must match preflight")
        incomplete = sum(
            1
            for flow in self.evidence.flows
            if flow.reconstruction_quality is ReconstructionQuality.INCOMPLETE
        )
        conflicting = sum(
            1
            for flow in self.evidence.flows
            if flow.reconstruction_quality is ReconstructionQuality.CONFLICTING
        )
        not_observable_certs = sum(
            1
            for handshake in self.evidence.handshakes
            if handshake.server_certificate_state is EvidenceState.NOT_OBSERVABLE
        )
        if limitations.incomplete_flow_count != incomplete:
            raise ValueError("limitations.incomplete_flow_count must match flows")
        if limitations.conflicting_flow_count != conflicting:
            raise ValueError("limitations.conflicting_flow_count must match flows")
        if limitations.not_observable_certificate_count != not_observable_certs:
            raise ValueError("limitations.not_observable_certificate_count must match handshakes")
        if limitations.unknown_check_count != overall.unknown_count:
            raise ValueError("limitations.unknown_check_count must match coverage")
        if limitations.not_observable_check_count != overall.not_observable_count:
            raise ValueError("limitations.not_observable_check_count must match coverage")
        return self


def canonical_report_json_schema() -> dict[str, Any]:
    """JSON Schema (validation mode) for the canonical report."""

    return CanonicalReport.model_json_schema(mode="validation")


def _rfc3339_z(value: datetime | None) -> str | None:
    if value is None:
        return None
    aware = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return aware.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
