"""Assemble a canonical report from a finished evidence document."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from securemail.domain.evidence.flow import ReconstructionQuality
from securemail.domain.evidence.run import EvidenceDocument, EvidenceState
from securemail.domain.reports.schema import (
    AdvisorySection,
    AnalystSection,
    ArtifactHash,
    Availability,
    CanonicalReport,
    CaptureLimitations,
    PostureSummary,
    RendererManifest,
    ReportManifest,
    SignatureMetadata,
    SourceRecord,
    SourceRecordKind,
)


class AssembleReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(min_length=1, max_length=160)
    analysis_run_id: str = Field(min_length=1, max_length=160)
    capture_filename: str = Field(min_length=1, max_length=255)
    generated_at: datetime | None = None
    dependency_versions: dict[str, str] = Field(default_factory=dict, max_length=32)


def assemble_report(
    document: EvidenceDocument,
    request: AssembleReportRequest,
    *,
    renderer: RendererManifest,
) -> CanonicalReport:
    """Wrap one `EvidenceDocument` in `securemail.report/v1` without re-scoring."""

    generated_at = request.generated_at or datetime.now(UTC)
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=UTC)
    else:
        generated_at = generated_at.astimezone(UTC)

    posture = document.posture
    incomplete = sum(
        1
        for flow in document.flows
        if flow.reconstruction_quality is ReconstructionQuality.INCOMPLETE
    )
    conflicting = sum(
        1
        for flow in document.flows
        if flow.reconstruction_quality is ReconstructionQuality.CONFLICTING
    )
    not_observable_certs = sum(
        1
        for handshake in document.handshakes
        if handshake.server_certificate_state is EvidenceState.NOT_OBSERVABLE
    )
    notes: list[str] = []
    if document.capture_preflight.truncated_packets_present:
        notes.append("Capture contains truncated packets; reconstruction may be incomplete.")
    if incomplete:
        notes.append(f"{incomplete} flow(s) have incomplete TCP reconstruction.")
    if conflicting:
        notes.append(f"{conflicting} flow(s) have conflicting TCP reconstructions.")
    if not_observable_certs:
        notes.append(
            f"{not_observable_certs} handshake(s) have certificates that are not observable."
        )
    capture_sha256 = document.run_identity.capture_sha256
    limitations = CaptureLimitations(
        truncated_packets_present=document.capture_preflight.truncated_packets_present,
        incomplete_flow_count=incomplete,
        conflicting_flow_count=conflicting,
        not_observable_certificate_count=not_observable_certs,
        unknown_check_count=posture.coverage.overall.unknown_count,
        not_observable_check_count=posture.coverage.overall.not_observable_count,
        notes=notes[:32],
    )
    manifest = ReportManifest(
        generated_at=generated_at,
        case_id=request.case_id,
        capture_id=capture_sha256[:32],
        analysis_run_id=request.analysis_run_id,
        source_capture_sha256=capture_sha256,
        working_copy_sha256=capture_sha256,
        working_copy_availability=Availability.PRESENT,
        source_records=[
            SourceRecord(
                kind=SourceRecordKind.CASE,
                identifier=request.case_id,
                availability=Availability.PRESENT,
            ),
            SourceRecord(
                kind=SourceRecordKind.CAPTURE,
                identifier=capture_sha256[:32],
                availability=Availability.PRESENT,
            ),
            SourceRecord(
                kind=SourceRecordKind.ANALYSIS_RUN,
                identifier=request.analysis_run_id,
                availability=Availability.PRESENT,
            ),
        ],
        artifact_hashes=[
            ArtifactHash(
                name=request.capture_filename,
                sha256=capture_sha256,
                availability=Availability.PRESENT,
            )
        ],
        renderer=renderer,
        signature=SignatureMetadata(),
        posture_summary=PostureSummary(
            assessment_state=posture.assessment_state,
            risk_score=posture.risk_score,
            finding_count=len(posture.prioritized_findings),
            unknown_count=posture.coverage.overall.unknown_count,
            not_observable_count=posture.coverage.overall.not_observable_count,
        ),
        configuration_digest=document.run_identity.configuration_digest,
        analyzer_bundle_digest=document.run_identity.analyzer_bundle_digest,
        policy_profile=document.run_identity.policy_profile.value,
        policy_pack_version=document.run_identity.policy_pack_version,
        trust_store_digest=document.run_identity.trust_store_digest,
        os_container=None,
        os_container_availability=Availability.UNAVAILABLE,
        dependency_versions=dict(request.dependency_versions),
    )
    return CanonicalReport(
        manifest=manifest,
        evidence=document,
        limitations=limitations,
        advisory=AdvisorySection(),
        analyst_conclusions=AnalystSection(),
    )
