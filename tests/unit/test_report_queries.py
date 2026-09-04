"""Bounded parsing and typed report-query tests."""

from __future__ import annotations

import pytest
from tests.support.fixture_harness import repo_root

from securemail.adapters.persistence.report_repository import FilesystemReportRepository
from securemail.adapters.reports.canonical_json import canonicalize
from securemail.application.report_queries import (
    CaseReportMismatchError,
    CaseReportNotFoundError,
    GetCaseReportRequest,
    InvalidCanonicalReportError,
    ListCasesRequest,
    ParseReportRequest,
    ReportTooLargeError,
    get_case_report,
    list_case_summaries,
    parse_report,
)
from securemail.ports.persistence import MAX_REPORT_BYTES, ReportCatalogEntry

DASHBOARD_ROOT = repo_root() / "tests" / "fixtures" / "dashboard"


class _MemoryRepository:
    def __init__(self, reports: dict[str, bytes]) -> None:
        self._reports = reports

    def list_reports(self) -> tuple[ReportCatalogEntry, ...]:
        return tuple(
            ReportCatalogEntry(case_id=case_id, size_bytes=len(payload))
            for case_id, payload in sorted(self._reports.items())
        )

    def get_report(self, case_id: str) -> bytes | None:
        return self._reports.get(case_id)


def test_parse_report_returns_canonical_bytes() -> None:
    raw = (DASHBOARD_ROOT / "dashboard_critical.report.json").read_bytes()
    parsed = parse_report(ParseReportRequest(report_bytes=raw), canonicalize=canonicalize)
    assert parsed.report.manifest.case_id == "dashboard_critical"
    assert parsed.canonical_bytes == canonicalize(parsed.report.model_dump(mode="json"))
    assert len(parsed.canonical_bytes) < len(raw)


@pytest.mark.parametrize("raw", [b"{", b"[]", b"\xff", b'{"schema_version":"wrong"}'])
def test_parse_report_rejects_invalid_input(raw: bytes) -> None:
    with pytest.raises(InvalidCanonicalReportError):
        parse_report(ParseReportRequest(report_bytes=raw), canonicalize=canonicalize)


def test_parse_report_rejects_oversize_before_json_decode() -> None:
    raw = b"{" + b"x" * MAX_REPORT_BYTES
    with pytest.raises(ReportTooLargeError):
        parse_report(ParseReportRequest(report_bytes=raw), canonicalize=canonicalize)


def test_case_summaries_are_typed_and_varied() -> None:
    result = list_case_summaries(
        ListCasesRequest(),
        repository=FilesystemReportRepository(DASHBOARD_ROOT),
        canonicalize=canonicalize,
    )
    summaries = {item.case_id: item for item in result.cases}
    assert set(summaries) == {
        "dashboard_attention",
        "dashboard_clear",
        "dashboard_critical",
    }
    assert summaries["dashboard_critical"].risk_score == 90
    assert summaries["dashboard_critical"].severity_counts.high == 1
    assert summaries["dashboard_critical"].advisory_present is True
    assert summaries["dashboard_attention"].risk_score == 50
    assert summaries["dashboard_attention"].analyst_conclusions_present is True
    assert summaries["dashboard_clear"].risk_score == 0
    assert summaries["dashboard_clear"].finding_count == 0


def test_case_lookup_requires_explicit_case_and_matching_manifest() -> None:
    raw = (DASHBOARD_ROOT / "dashboard_critical.report.json").read_bytes()
    repository = _MemoryRepository({"requested_case": raw})
    with pytest.raises(CaseReportMismatchError):
        get_case_report(
            GetCaseReportRequest(case_id="requested_case"),
            repository=repository,
            canonicalize=canonicalize,
        )
    with pytest.raises(CaseReportNotFoundError):
        get_case_report(
            GetCaseReportRequest(case_id="missing"),
            repository=repository,
            canonicalize=canonicalize,
        )


def test_dashboard_fixture_provenance_matches_canonical_reports() -> None:
    import json

    from securemail.adapters.reports.canonical_json import sha256_digest
    from securemail.domain.reports.schema import CanonicalReport

    provenance = json.loads((DASHBOARD_ROOT / "provenance.json").read_text(encoding="utf-8"))
    reports = provenance["reports"]
    assert isinstance(reports, list)
    assert len(reports) == 3
    for item in reports:
        assert isinstance(item, dict)
        case_id = str(item["case_id"])
        report_path = DASHBOARD_ROOT / f"{case_id}.report.json"
        report = CanonicalReport.model_validate_json(report_path.read_bytes())
        digest = sha256_digest(canonicalize(report.model_dump(mode="json")))
        assert digest == item["canonical_json_sha256"]
