"""Worker pipeline: analyze, assemble, advise, render, publish."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

from securemail.application.advisory_pipeline import attach_advisories_with_history
from securemail.application.assemble_report import AssembleReportRequest, assemble_report
from securemail.application.render_report import (
    CanonicalizeFn,
    RenderedReport,
    RenderHtmlFn,
    RenderPdfFn,
    render_report,
)
from securemail.application.run_analysis import DEFAULT_EXPIRY_WARNING_SECONDS, AnalyzeRequest
from securemail.domain.evidence.run import EvidenceDocument, PolicyProfile
from securemail.domain.jobs.models import (
    MAX_HTML_BYTES,
    MAX_PDF_BYTES,
    AnalysisJob,
    AnalysisStage,
    AnalysisStatus,
    ArtifactAvailability,
)
from securemail.domain.reports.schema import RendererManifest
from securemail.ports.jobs import AnalysisJobStore, JobNotFoundError
from securemail.ports.ml import AnomalyScorer
from securemail.ports.ml_history import MlHistoryStore
from securemail.ports.persistence import CatalogPublisher

AnalyzeFn = Callable[[AnalyzeRequest], EvidenceDocument]
DigestFn = Callable[[bytes], str]


class CaptureWorkflowError(Exception):
    """Raised when a queued capture cannot complete."""


def _cancelled(store: AnalysisJobStore, run_id: str) -> bool:
    return store.is_cancel_requested(run_id)


def _fail(store: AnalysisJobStore, run_id: str, message: str) -> AnalysisJob:
    return store.update_job(
        run_id,
        status=AnalysisStatus.FAILED,
        error_message=message[:1000],
    )


def _mark_cancelled(store: AnalysisJobStore, run_id: str) -> AnalysisJob:
    return store.update_job(run_id, status=AnalysisStatus.CANCELLED, error_message=None)


def execute_capture_job(
    run_id: str,
    *,
    job_store: AnalysisJobStore,
    history_store: MlHistoryStore,
    catalog: CatalogPublisher,
    analyze: AnalyzeFn,
    renderer: RendererManifest,
    scorers: Sequence[AnomalyScorer],
    canonicalize: CanonicalizeFn,
    digest: DigestFn,
    render_html: RenderHtmlFn,
    render_pdf: RenderPdfFn,
    dependency_versions: dict[str, str],
) -> AnalysisJob:
    """Run one claimed job through analysis, ML, render, and catalog publish."""

    job = job_store.get_job(run_id)
    if job is None:
        raise JobNotFoundError(f"unknown analysis run: {run_id}")
    if job.status is not AnalysisStatus.RUNNING:
        return job
    try:
        return _execute_stages(
            job,
            job_store=job_store,
            history_store=history_store,
            catalog=catalog,
            analyze=analyze,
            renderer=renderer,
            scorers=scorers,
            canonicalize=canonicalize,
            digest=digest,
            render_html=render_html,
            render_pdf=render_pdf,
            dependency_versions=dependency_versions,
        )
    except Exception as exc:
        return _fail(job_store, run_id, str(exc) or type(exc).__name__)


def _execute_stages(
    job: AnalysisJob,
    *,
    job_store: AnalysisJobStore,
    history_store: MlHistoryStore,
    catalog: CatalogPublisher,
    analyze: AnalyzeFn,
    renderer: RendererManifest,
    scorers: Sequence[AnomalyScorer],
    canonicalize: CanonicalizeFn,
    digest: DigestFn,
    render_html: RenderHtmlFn,
    render_pdf: RenderPdfFn,
    dependency_versions: dict[str, str],
) -> AnalysisJob:
    run_id = job.run_id
    if _cancelled(job_store, run_id):
        return _mark_cancelled(job_store, run_id)

    job_store.update_job(run_id, stage=AnalysisStage.DETERMINISTIC_ANALYSIS)
    capture_path: Path = job_store.capture_path(run_id)
    try:
        profile = PolicyProfile(job.policy_profile)
    except ValueError as exc:
        raise CaptureWorkflowError(f"unknown policy profile: {job.policy_profile}") from exc
    evidence = analyze(
        AnalyzeRequest(
            capture_path=capture_path,
            expiry_warning_seconds=DEFAULT_EXPIRY_WARNING_SECONDS,
            expected_hostname=job.expected_hostname,
            policy_profile=profile,
        )
    )
    if _cancelled(job_store, run_id):
        return _mark_cancelled(job_store, run_id)

    job_store.update_job(run_id, stage=AnalysisStage.POLICY_SCORING)
    report = assemble_report(
        evidence,
        AssembleReportRequest(
            case_id=job.case_id,
            analysis_run_id=run_id,
            capture_filename=f"capture.{job.capture_format}",
            dependency_versions=dependency_versions,
        ),
        renderer=renderer,
    )
    if _cancelled(job_store, run_id):
        return _mark_cancelled(job_store, run_id)

    job_store.update_job(run_id, stage=AnalysisStage.ML_ADVISORY)
    history = history_store.load_windows()
    advised, new_windows = attach_advisories_with_history(
        report,
        scorers=scorers,
        history=history,
        cohort="local",
    )
    if advised.evidence.findings is not evidence.findings:
        raise CaptureWorkflowError("advisory pipeline mutated deterministic findings")
    history_store.append_windows(new_windows)
    if _cancelled(job_store, run_id):
        return _mark_cancelled(job_store, run_id)

    job_store.update_job(run_id, stage=AnalysisStage.REPORT_RENDERING)
    rendered: RenderedReport = render_report(
        advised,
        ("json", "html", "pdf"),
        canonicalize=canonicalize,
        digest=digest,
        render_html=render_html,
        render_pdf=render_pdf,
    )
    if rendered.html is None or rendered.pdf is None:
        raise CaptureWorkflowError("HTML and PDF artifacts are required")
    html_bytes = rendered.html.encode("utf-8")
    if len(html_bytes) > MAX_HTML_BYTES:
        raise CaptureWorkflowError(f"HTML artifact exceeds {MAX_HTML_BYTES} bytes")
    if len(rendered.pdf) > MAX_PDF_BYTES:
        raise CaptureWorkflowError(f"PDF artifact exceeds {MAX_PDF_BYTES} bytes")
    job_store.write_artifact(run_id, "report.json", rendered.json_bytes)
    job_store.write_artifact(run_id, "report.html", html_bytes)
    job_store.write_artifact(run_id, "report.pdf", rendered.pdf)
    if _cancelled(job_store, run_id):
        return _mark_cancelled(job_store, run_id)

    job_store.update_job(run_id, stage=AnalysisStage.PUBLICATION)
    catalog.publish_report(job.case_id, rendered.json_bytes)
    return job_store.update_job(
        run_id,
        status=AnalysisStatus.COMPLETED,
        stage=AnalysisStage.PUBLICATION,
        artifacts=ArtifactAvailability(json=True, html=True, pdf=True),
        error_message=None,
    )


def process_next_job(
    *,
    job_store: AnalysisJobStore,
    history_store: MlHistoryStore,
    catalog: CatalogPublisher,
    analyze: AnalyzeFn,
    renderer: RendererManifest,
    scorers: Sequence[AnomalyScorer],
    canonicalize: CanonicalizeFn,
    digest: DigestFn,
    render_html: RenderHtmlFn,
    render_pdf: RenderPdfFn,
    dependency_versions: dict[str, str],
) -> AnalysisJob | None:
    claimed = job_store.claim_next()
    if claimed is None:
        return None
    return execute_capture_job(
        claimed.run_id,
        job_store=job_store,
        history_store=history_store,
        catalog=catalog,
        analyze=analyze,
        renderer=renderer,
        scorers=scorers,
        canonicalize=canonicalize,
        digest=digest,
        render_html=render_html,
        render_pdf=render_pdf,
        dependency_versions=dependency_versions,
    )
