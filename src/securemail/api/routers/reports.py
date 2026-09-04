"""Thin HTTP routes over canonical-report application queries."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Request, Response, status
from pydantic import BaseModel, ConfigDict

from securemail.api.dependencies import ApiDependenciesDep
from securemail.application.report_queries import (
    CaseReportMismatchError,
    CaseReportNotFoundError,
    GetCaseReportRequest,
    InvalidCanonicalReportError,
    ListCasesRequest,
    ListCasesResult,
    ParseReportRequest,
    ReportCatalogError,
    ReportTooLargeError,
    get_case_report,
    list_case_summaries,
    parse_report,
)
from securemail.ports.persistence import MAX_REPORT_BYTES

router = APIRouter(prefix="/api/v1")


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: str


class ErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    detail: str


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get(
    "/cases",
    response_model=ListCasesResult,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ErrorResponse}},
)
def list_cases(dependencies: ApiDependenciesDep) -> ListCasesResult:
    try:
        return list_case_summaries(
            ListCasesRequest(),
            repository=dependencies.report_repository,
            canonicalize=dependencies.canonicalize,
        )
    except (
        CaseReportMismatchError,
        InvalidCanonicalReportError,
        ReportCatalogError,
        ReportTooLargeError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="report catalog unavailable",
        ) from exc


@router.get(
    "/cases/{case_id}/report",
    responses={
        status.HTTP_200_OK: {"content": {"application/json": {}}},
        status.HTTP_404_NOT_FOUND: {"model": ErrorResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ErrorResponse},
    },
)
def read_case_report(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    ],
    dependencies: ApiDependenciesDep,
) -> Response:
    try:
        result = get_case_report(
            GetCaseReportRequest(case_id=case_id),
            repository=dependencies.report_repository,
            canonicalize=dependencies.canonicalize,
        )
    except (CaseReportMismatchError, CaseReportNotFoundError) as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="case report not found",
        ) from exc
    except (
        InvalidCanonicalReportError,
        ReportCatalogError,
        ReportTooLargeError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="case report unavailable",
        ) from exc
    return Response(content=result.canonical_bytes, media_type="application/json")


@router.post(
    "/reports/preview",
    responses={
        status.HTTP_200_OK: {"content": {"application/json": {}}},
        status.HTTP_400_BAD_REQUEST: {"model": ErrorResponse},
        status.HTTP_413_CONTENT_TOO_LARGE: {"model": ErrorResponse},
    },
)
async def preview_report(request: Request, dependencies: ApiDependenciesDep) -> Response:
    payload = bytearray()
    async for chunk in request.stream():
        if len(payload) + len(chunk) > MAX_REPORT_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"report input exceeds {MAX_REPORT_BYTES} bytes",
            )
        payload.extend(chunk)
    try:
        parsed = parse_report(
            ParseReportRequest(report_bytes=bytes(payload)),
            canonicalize=dependencies.canonicalize,
        )
    except ReportTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=str(exc),
        ) from exc
    except InvalidCanonicalReportError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    return Response(content=parsed.canonical_bytes, media_type="application/json")
