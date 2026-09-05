"""Read-side queries for capture-analysis jobs and downloadable artifacts."""

from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from securemail.application.render_report import (
    CanonicalizeFn,
    RenderHtmlFn,
    RenderPdfFn,
    ReportError,
    render_report,
)
from securemail.application.report_queries import GetCaseReportRequest, get_case_report
from securemail.domain.jobs.models import AnalysisJob, AnalysisStatus, ArtifactAvailability
from securemail.ports.jobs import AnalysisJobStore, JobNotFoundError
from securemail.ports.persistence import ReportRepository

DigestFn = Callable[[bytes], str]


class AnalysisQueryError(Exception):
    """Expected job-query failure."""


class ArtifactNotReadyError(AnalysisQueryError):
    """Raised when a download is requested before publication."""


class GetAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str = Field(min_length=1, max_length=160)


class CancelAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str = Field(min_length=1, max_length=160)


class AnalysisStatusView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    case_id: str
    status: AnalysisStatus
    stage: str
    capture_sha256: str | None
    original_filename: str
    policy_profile: str
    expected_hostname: str | None
    created_at: str
    updated_at: str
    error_message: str | None
    artifacts: ArtifactAvailability
    cancel_requested: bool


def job_status_view(job: AnalysisJob) -> AnalysisStatusView:
    dumped = job.model_dump(mode="json")
    return AnalysisStatusView(
        run_id=job.run_id,
        case_id=job.case_id,
        status=job.status,
        stage=job.stage.value,
        capture_sha256=job.capture_sha256,
        original_filename=job.original_filename,
        policy_profile=job.policy_profile,
        expected_hostname=job.expected_hostname,
        created_at=str(dumped["created_at"]),
        updated_at=str(dumped["updated_at"]),
        error_message=job.error_message,
        artifacts=job.artifacts,
        cancel_requested=job.cancel_requested,
    )


def get_analysis(request: GetAnalysisRequest, *, job_store: AnalysisJobStore) -> AnalysisJob:
    job = job_store.get_job(request.run_id)
    if job is None:
        raise JobNotFoundError("analysis run not found")
    return job


def cancel_analysis(request: CancelAnalysisRequest, *, job_store: AnalysisJobStore) -> AnalysisJob:
    return job_store.request_cancel(request.run_id)


def read_job_artifact(
    run_id: str,
    name: str,
    *,
    job_store: AnalysisJobStore,
) -> bytes:
    job = get_analysis(GetAnalysisRequest(run_id=run_id), job_store=job_store)
    if job.status is not AnalysisStatus.COMPLETED:
        raise ArtifactNotReadyError("analysis artifacts are not ready")
    payload = job_store.read_artifact(run_id, name)
    if payload is None:
        raise ArtifactNotReadyError("analysis artifact is missing")
    return payload


def render_case_artifact(
    case_id: str,
    fmt: str,
    *,
    repository: ReportRepository,
    canonicalize: CanonicalizeFn,
    digest: DigestFn,
    render_html: RenderHtmlFn,
    render_pdf: RenderPdfFn,
) -> bytes:
    result = get_case_report(
        GetCaseReportRequest(case_id=case_id),
        repository=repository,
        canonicalize=canonicalize,
    )
    try:
        rendered = render_report(
            result.report,
            (fmt,),
            canonicalize=canonicalize,
            digest=digest,
            render_html=render_html,
            render_pdf=render_pdf,
        )
    except ReportError as exc:
        raise ArtifactNotReadyError(str(exc)) from exc
    if fmt == "json":
        return rendered.json_bytes
    if fmt == "html":
        if rendered.html is None:
            raise ArtifactNotReadyError("HTML artifact is unavailable")
        return rendered.html.encode("utf-8")
    if rendered.pdf is None:
        raise ArtifactNotReadyError("PDF artifact is unavailable")
    return rendered.pdf
