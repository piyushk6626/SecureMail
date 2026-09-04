"""Bounded canonical-report parsing and read-only dashboard queries."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from securemail.domain import evidence as _evidence_models
from securemail.domain.findings.posture import AssessmentState
from securemail.domain.reports.schema import CanonicalReport
from securemail.ports.persistence import (
    MAX_REPORT_BYTES,
    ReportRepository,
    ReportRepositoryError,
)

# Evidence models must finish loading before findings; otherwise
# `from securemail.api.main import app` hits a circular import.
_ = _evidence_models.EvidenceDocument

CanonicalizeFn = Callable[[Mapping[str, Any]], bytes]


class ReportQueryError(Exception):
    """Base class for expected report-query failures."""


class ReportTooLargeError(ReportQueryError):
    """Raised before parsing a report larger than the fixed input limit."""


class InvalidCanonicalReportError(ReportQueryError):
    """Raised when bytes are not a valid ``securemail.report/v1`` report."""


class CaseReportNotFoundError(ReportQueryError):
    """Raised when no report is explicitly cataloged for a case."""


class CaseReportMismatchError(ReportQueryError):
    """Raised when catalog and report manifest case IDs differ."""


class ReportCatalogError(ReportQueryError):
    """Raised when the read-only report catalog cannot be queried safely."""


class ParseReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    report_bytes: bytes


class ParsedReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    report: CanonicalReport
    canonical_bytes: bytes


class FindingSeverityCounts(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    high: int = Field(ge=0)
    medium: int = Field(ge=0)
    low: int = Field(ge=0)
    informational: int = Field(ge=0)


class CaseSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(min_length=1, max_length=160)
    generated_at: datetime
    assessment_state: AssessmentState
    risk_score: int | None = Field(default=None, ge=0, le=100)
    finding_count: int = Field(ge=0)
    severity_counts: FindingSeverityCounts
    unknown_count: int = Field(ge=0)
    not_observable_count: int = Field(ge=0)
    advisory_present: bool
    analyst_conclusions_present: bool


class ListCasesRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ListCasesResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    cases: list[CaseSummary]


class GetCaseReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(min_length=1, max_length=160)


class GetCaseReportResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    report: CanonicalReport
    canonical_bytes: bytes


def parse_report(
    request: ParseReportRequest,
    *,
    canonicalize: CanonicalizeFn,
) -> ParsedReport:
    """Validate bounded UTF-8 JSON and return its RFC 8785 representation."""

    raw = request.report_bytes
    if len(raw) > MAX_REPORT_BYTES:
        raise ReportTooLargeError(f"report input exceeds {MAX_REPORT_BYTES} bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidCanonicalReportError("report input must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise InvalidCanonicalReportError("report JSON must be an object")
    try:
        report = CanonicalReport.model_validate(payload)
        canonical_bytes = canonicalize(report.model_dump(mode="json"))
    except (ValidationError, TypeError, ValueError) as exc:
        raise InvalidCanonicalReportError("report does not match securemail.report/v1") from exc
    return ParsedReport(report=report, canonical_bytes=canonical_bytes)


def list_case_summaries(
    request: ListCasesRequest,
    *,
    repository: ReportRepository,
    canonicalize: CanonicalizeFn,
) -> ListCasesResult:
    """Return summaries assembled from validated catalog reports."""

    del request
    try:
        entries = repository.list_reports()
    except ReportRepositoryError as exc:
        raise ReportCatalogError("report catalog is unavailable") from exc

    summaries: list[CaseSummary] = []
    for entry in entries:
        try:
            raw = repository.get_report(entry.case_id)
        except ReportRepositoryError as exc:
            raise ReportCatalogError("report catalog is unavailable") from exc
        if raw is None:
            raise ReportCatalogError("cataloged report is unavailable")
        parsed = parse_report(ParseReportRequest(report_bytes=raw), canonicalize=canonicalize)
        summaries.append(_case_summary(entry.case_id, parsed.report))
    return ListCasesResult(cases=summaries)


def get_case_report(
    request: GetCaseReportRequest,
    *,
    repository: ReportRepository,
    canonicalize: CanonicalizeFn,
) -> GetCaseReportResult:
    """Look up only the requested explicit case and verify its manifest ID."""

    try:
        raw = repository.get_report(request.case_id)
    except ReportRepositoryError as exc:
        raise ReportCatalogError("report catalog is unavailable") from exc
    if raw is None:
        raise CaseReportNotFoundError("case report not found")
    parsed = parse_report(ParseReportRequest(report_bytes=raw), canonicalize=canonicalize)
    if parsed.report.manifest.case_id != request.case_id:
        raise CaseReportMismatchError("case report manifest does not match requested case")
    return GetCaseReportResult(
        case_id=request.case_id,
        report=parsed.report,
        canonical_bytes=parsed.canonical_bytes,
    )


def _case_summary(case_id: str, report: CanonicalReport) -> CaseSummary:
    if report.manifest.case_id != case_id:
        raise CaseReportMismatchError("case report manifest does not match catalog case")
    posture = report.evidence.posture
    counts = Counter(item.severity.value for item in posture.prioritized_findings)
    return CaseSummary(
        case_id=case_id,
        generated_at=report.manifest.generated_at,
        assessment_state=posture.assessment_state,
        risk_score=posture.risk_score,
        finding_count=len(posture.prioritized_findings),
        severity_counts=FindingSeverityCounts(
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            informational=counts["informational"],
        ),
        unknown_count=posture.coverage.overall.unknown_count,
        not_observable_count=posture.coverage.overall.not_observable_count,
        advisory_present=report.advisory.present,
        analyst_conclusions_present=report.analyst_conclusions.present,
    )
