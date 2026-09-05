"""EvidenceDocument to CanonicalReport assembly."""

from __future__ import annotations

from tests.support.fixture_harness import load_golden_report

from securemail.adapters.reports.html_renderer import renderer_manifest
from securemail.application.assemble_report import AssembleReportRequest, assemble_report
from securemail.domain.reports.schema import CanonicalReport


def test_assemble_report_tracks_run_identity_and_limitations() -> None:
    source = CanonicalReport.model_validate(load_golden_report())
    assembled = assemble_report(
        source.evidence,
        AssembleReportRequest(
            case_id="assembled_case",
            analysis_run_id="rtestrun01",
            capture_filename="capture.pcapng",
            dependency_versions={"jinja2": "3.1.6"},
        ),
        renderer=renderer_manifest(pdf_renderer_version="69.0"),
    )
    assert assembled.schema_version == "securemail.report/v1"
    assert assembled.manifest.case_id == "assembled_case"
    assert assembled.manifest.source_capture_sha256 == source.evidence.run_identity.capture_sha256
    assert assembled.evidence.findings == source.evidence.findings
    assert assembled.limitations.incomplete_flow_count >= 1
    assert assembled.advisory.present is False
    assert assembled.limitations.unknown_check_count == (
        source.evidence.posture.coverage.overall.unknown_count
    )
