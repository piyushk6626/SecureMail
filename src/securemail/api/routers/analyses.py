"""Thin HTTP routes for capture upload, job status, and report downloads."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, File, Form, HTTPException, Path, UploadFile, status
from fastapi.responses import Response

from securemail.api.dependencies import ApiDependenciesDep
from securemail.application.analysis_queries import (
    ArtifactNotReadyError,
    CancelAnalysisRequest,
    GetAnalysisRequest,
    cancel_analysis,
    get_analysis,
    job_status_view,
    read_job_artifact,
    render_case_artifact,
)
from securemail.application.capture_intake import (
    CaptureIntakeError,
    CaptureIntakeRequest,
    CaptureTooLargeError,
    ingest_capture,
)
from securemail.application.render_report import ReportError
from securemail.application.report_queries import (
    CaseReportMismatchError,
    CaseReportNotFoundError,
    InvalidCanonicalReportError,
    ReportCatalogError,
    ReportTooLargeError,
)
from securemail.application.run_analysis import InvalidCaptureError
from securemail.domain.evidence.run import PolicyProfile
from securemail.ports.jobs import (
    AnalysisJobStore,
    JobConflictError,
    JobNotFoundError,
    StorageQuotaError,
)
from securemail.ports.persistence import ReportRepositoryError

router = APIRouter(prefix="/api/v1")


def _require_jobs(dependencies: ApiDependenciesDep) -> AnalysisJobStore:
    if dependencies.job_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="capture analysis is not configured",
        )
    return dependencies.job_store


def _safe_filename(stem: str, suffix: str) -> str:
    return quote(f"securemail-{stem}{suffix}", safe="._-")


def _upload_chunks(upload: UploadFile) -> Iterator[bytes]:
    while True:
        chunk = upload.file.read(64 * 1024)
        if not chunk:
            break
        yield chunk


@router.post("/analyses", status_code=status.HTTP_202_ACCEPTED)
def create_analysis(
    dependencies: ApiDependenciesDep,
    file: Annotated[UploadFile, File()],
    policy_profile: Annotated[str, Form()] = PolicyProfile.IETF_CURRENT.value,
    expected_hostname: Annotated[str | None, Form()] = None,
    case_id: Annotated[str | None, Form()] = None,
) -> Response:
    job_store = _require_jobs(dependencies)
    filename = file.filename or ""
    try:
        profile = PolicyProfile(policy_profile)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="unknown policy profile",
        ) from exc
    hostname = expected_hostname.strip() if expected_hostname else None
    try:
        job = ingest_capture(
            CaptureIntakeRequest(
                original_filename=filename,
                policy_profile=profile,
                expected_hostname=hostname or None,
                case_id=case_id,
                max_capture_bytes=dependencies.max_capture_bytes,
            ),
            _upload_chunks(file),
            job_store=job_store,
        )
    except CaptureTooLargeError as exc:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=str(exc)) from exc
    except (InvalidCaptureError, CaptureIntakeError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except StorageQuotaError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="capture storage quota exceeded",
        ) from None
    return Response(
        content=job_status_view(job).model_dump_json(),
        media_type="application/json",
        status_code=status.HTTP_202_ACCEPTED,
    )


@router.get("/analyses/{run_id}")
def read_analysis(
    run_id: Annotated[
        str,
        Path(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    ],
    dependencies: ApiDependenciesDep,
) -> Response:
    job_store = _require_jobs(dependencies)
    try:
        job = get_analysis(GetAnalysisRequest(run_id=run_id), job_store=job_store)
    except JobNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return Response(content=job_status_view(job).model_dump_json(), media_type="application/json")


@router.post("/analyses/{run_id}/cancel")
def cancel_analysis_route(
    run_id: Annotated[
        str,
        Path(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    ],
    dependencies: ApiDependenciesDep,
) -> Response:
    job_store = _require_jobs(dependencies)
    try:
        job = cancel_analysis(CancelAnalysisRequest(run_id=run_id), job_store=job_store)
    except JobNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except JobConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return Response(content=job_status_view(job).model_dump_json(), media_type="application/json")


@router.get("/analyses/{run_id}/report")
def download_analysis_json(
    run_id: Annotated[
        str,
        Path(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    ],
    dependencies: ApiDependenciesDep,
) -> Response:
    return _job_download(run_id, "report.json", "application/json", ".json", dependencies)


@router.get("/analyses/{run_id}/report.html")
def download_analysis_html(
    run_id: Annotated[
        str,
        Path(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    ],
    dependencies: ApiDependenciesDep,
) -> Response:
    return _job_download(run_id, "report.html", "text/html; charset=utf-8", ".html", dependencies)


@router.get("/analyses/{run_id}/report.pdf")
def download_analysis_pdf(
    run_id: Annotated[
        str,
        Path(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    ],
    dependencies: ApiDependenciesDep,
) -> Response:
    return _job_download(run_id, "report.pdf", "application/pdf", ".pdf", dependencies)


@router.get("/cases/{case_id}/report.html")
def download_case_html(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    ],
    dependencies: ApiDependenciesDep,
) -> Response:
    return _case_download(case_id, "html", "text/html; charset=utf-8", ".html", dependencies)


@router.get("/cases/{case_id}/report.pdf")
def download_case_pdf(
    case_id: Annotated[
        str,
        Path(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    ],
    dependencies: ApiDependenciesDep,
) -> Response:
    return _case_download(case_id, "pdf", "application/pdf", ".pdf", dependencies)


def _job_download(
    run_id: str,
    name: str,
    media_type: str,
    suffix: str,
    dependencies: ApiDependenciesDep,
) -> Response:
    job_store = _require_jobs(dependencies)
    try:
        job = get_analysis(GetAnalysisRequest(run_id=run_id), job_store=job_store)
        payload = read_job_artifact(run_id, name, job_store=job_store)
    except JobNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ArtifactNotReadyError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    filename = _safe_filename(job.case_id, suffix)
    return Response(
        content=payload,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _case_download(
    case_id: str,
    fmt: str,
    media_type: str,
    suffix: str,
    dependencies: ApiDependenciesDep,
) -> Response:
    if (
        dependencies.render_html is None
        or dependencies.render_pdf is None
        or dependencies.digest is None
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="report rendering is not configured",
        )
    try:
        payload = render_case_artifact(
            case_id,
            fmt,
            repository=dependencies.report_repository,
            canonicalize=dependencies.canonicalize,
            digest=dependencies.digest,
            render_html=dependencies.render_html,
            render_pdf=dependencies.render_pdf,
        )
    except (CaseReportMismatchError, CaseReportNotFoundError) as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="case report not found"
        ) from exc
    except (
        InvalidCanonicalReportError,
        ReportCatalogError,
        ReportTooLargeError,
        ReportRepositoryError,
        ArtifactNotReadyError,
        ReportError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="case report unavailable",
        ) from exc
    filename = _safe_filename(case_id, suffix)
    return Response(
        content=payload,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
