"""Composition root: the only module that imports a port and its adapter."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

import typer

from securemail.adapters.analyzers.capinfos_runner import DockerCapinfosRunner
from securemail.adapters.analyzers.tshark_runner import DockerTSharkRunner
from securemail.adapters.analyzers.zeek_runner import DockerZeekRunner
from securemail.adapters.artifacts.certificate_store import CertificateStore
from securemail.adapters.pki.trust_store import load_trust_store_snapshot
from securemail.adapters.reference_data.iana_tls_parameters import load_iana_tls_parameters
from securemail.adapters.reference_data.policy_packs import PolicyPackError, load_policy_pack
from securemail.application.run_analysis import (
    DEFAULT_EXPIRY_WARNING_SECONDS,
    AnalysisError,
    AnalyzeRequest,
    run_analysis,
    score_findings,
)
from securemail.application.stub_analyze import stub_analyze
from securemail.domain.evidence.run import EvidenceDocument, PolicyProfile

if TYPE_CHECKING:
    from fastapi import FastAPI

    from securemail.application.render_report import RenderedReport
    from securemail.application.report_queries import ParsedReport, ParseReportRequest
    from securemail.domain.jobs.models import AnalysisJob
    from securemail.domain.ml.models import EvaluationReport
    from securemail.domain.reports.schema import CanonicalReport, RendererManifest


def _analyze(
    capture: Path,
    *,
    artifact_root: Path | None = None,
    analysis_time: datetime | None = None,
    expiry_warning_seconds: int = DEFAULT_EXPIRY_WARNING_SECONDS,
    expected_hostname: str | None = None,
    policy_profile: PolicyProfile = PolicyProfile.IETF_CURRENT,
) -> EvidenceDocument:
    store = CertificateStore(root=artifact_root)
    try:
        policy_pack, policy_pack_digest = load_policy_pack(policy_profile)
    except PolicyPackError as exc:
        raise AnalysisError(str(exc)) from exc
    return run_analysis(
        AnalyzeRequest(
            capture_path=capture,
            analysis_time=analysis_time,
            expiry_warning_seconds=expiry_warning_seconds,
            expected_hostname=expected_hostname,
            policy_profile=policy_profile,
        ),
        zeek_runner=DockerZeekRunner(),
        preflight_runner=DockerCapinfosRunner(),
        tshark_runner=DockerTSharkRunner(),
        tls_parameters=load_iana_tls_parameters(),
        artifact_store=store,
        trust_snapshot=load_trust_store_snapshot(),
        policy_pack=policy_pack,
        policy_pack_digest=policy_pack_digest,
    )


def _render_report(report: CanonicalReport, *, formats: tuple[str, ...]) -> RenderedReport:
    from securemail.adapters.reports.canonical_json import canonicalize, sha256_digest
    from securemail.adapters.reports.html_renderer import render_html
    from securemail.adapters.reports.pdf_renderer import render_pdf
    from securemail.application.render_report import render_report

    return render_report(
        report,
        formats,
        canonicalize=canonicalize,
        digest=sha256_digest,
        render_html=render_html,
        render_pdf=render_pdf,
    )


def _parse_report(request: ParseReportRequest) -> ParsedReport:
    from securemail.adapters.reports.canonical_json import canonicalize
    from securemail.application.report_queries import parse_report

    return parse_report(request, canonicalize=canonicalize)


def _evaluate_ml(cohort_dir: Path) -> EvaluationReport:
    from securemail.adapters.ml.baselines import BaselineAnomalyScorer
    from securemail.adapters.ml.isolation_forest import IsolationForestScorer
    from securemail.application.advisory_pipeline import evaluate_cohort_dir

    return evaluate_cohort_dir(
        cohort_dir,
        baseline=BaselineAnomalyScorer(),
        challenger=IsolationForestScorer(),
    )


def _apply_advisory(report: CanonicalReport) -> CanonicalReport:
    from securemail.adapters.ml.baselines import BaselineAnomalyScorer
    from securemail.adapters.ml.isolation_forest import IsolationForestScorer
    from securemail.application.advisory_pipeline import attach_advisories

    return attach_advisories(
        report,
        scorers=(BaselineAnomalyScorer(), IsolationForestScorer()),
        cohort="capture",
    )


def _renderer_bundle() -> tuple[RendererManifest, dict[str, str]]:
    import jinja2

    from securemail.adapters.reports.html_renderer import renderer_manifest
    from securemail.adapters.reports.pdf_renderer import weasyprint_version

    versions = {"jinja2": jinja2.__version__}
    pdf_version = weasyprint_version()
    versions["weasyprint"] = pdf_version
    return renderer_manifest(pdf_renderer_version=pdf_version), versions


def _analyze_from_request(request: AnalyzeRequest) -> EvidenceDocument:
    return _analyze(
        request.capture_path,
        analysis_time=request.analysis_time,
        expiry_warning_seconds=request.expiry_warning_seconds,
        expected_hostname=request.expected_hostname,
        policy_profile=request.policy_profile,
    )


def _worker_analyze(request: AnalyzeRequest) -> EvidenceDocument:
    if os.environ.get("SECUREMAIL_ANALYSIS_STUB") == "1":
        return stub_analyze(request)
    return _analyze_from_request(request)


def run_capture_worker_loop() -> None:
    """Block and drain queued capture jobs. Used by ``python -m securemail.worker``."""

    import time

    from securemail.adapters.ml.baselines import BaselineAnomalyScorer
    from securemail.adapters.ml.isolation_forest import IsolationForestScorer
    from securemail.adapters.persistence.job_store import FilesystemJobStore
    from securemail.adapters.persistence.ml_history_store import FilesystemMlHistoryStore
    from securemail.adapters.persistence.writable_catalog import FilesystemCatalogPublisher
    from securemail.adapters.reports.canonical_json import canonicalize, sha256_digest
    from securemail.adapters.reports.html_renderer import render_html
    from securemail.adapters.reports.pdf_renderer import render_pdf
    from securemail.application.analysis_workflow import process_next_job

    data_root = Path(
        os.environ.get("SECUREMAIL_DATA_ROOT") or os.environ.get("SECUREMAIL_REPORT_ROOT") or ""
    )
    if not data_root:
        raise RuntimeError("SECUREMAIL_DATA_ROOT or SECUREMAIL_REPORT_ROOT is required")
    report_root = Path(os.environ.get("SECUREMAIL_REPORT_ROOT") or data_root)
    renderer, versions = _renderer_bundle()
    job_store = FilesystemJobStore(data_root)
    history_store = FilesystemMlHistoryStore(data_root)
    catalog = FilesystemCatalogPublisher(report_root)
    while True:
        process_next_job(
            job_store=job_store,
            history_store=history_store,
            catalog=catalog,
            analyze=_worker_analyze,
            renderer=renderer,
            scorers=(BaselineAnomalyScorer(), IsolationForestScorer()),
            canonicalize=canonicalize,
            digest=sha256_digest,
            render_html=render_html,
            render_pdf=render_pdf,
            dependency_versions=versions,
        )
        time.sleep(0.5)


def process_pending_analysis(
    *,
    data_root: Path,
    report_root: Path | None = None,
) -> AnalysisJob | None:
    """Run at most one queued job. Used by tests instead of the worker subprocess."""

    from securemail.adapters.ml.baselines import BaselineAnomalyScorer
    from securemail.adapters.ml.isolation_forest import IsolationForestScorer
    from securemail.adapters.persistence.job_store import FilesystemJobStore
    from securemail.adapters.persistence.ml_history_store import FilesystemMlHistoryStore
    from securemail.adapters.persistence.writable_catalog import FilesystemCatalogPublisher
    from securemail.adapters.reports.canonical_json import canonicalize, sha256_digest
    from securemail.adapters.reports.html_renderer import render_html
    from securemail.adapters.reports.pdf_renderer import render_pdf
    from securemail.application.analysis_workflow import process_next_job

    renderer, versions = _renderer_bundle()
    return process_next_job(
        job_store=FilesystemJobStore(data_root),
        history_store=FilesystemMlHistoryStore(data_root),
        catalog=FilesystemCatalogPublisher(report_root or data_root),
        analyze=_worker_analyze,
        renderer=renderer,
        scorers=(BaselineAnomalyScorer(), IsolationForestScorer()),
        canonicalize=canonicalize,
        digest=sha256_digest,
        render_html=render_html,
        render_pdf=render_pdf,
        dependency_versions=versions,
    )


def create_cli() -> typer.Typer:
    from securemail.api.cli.main import build_app

    return build_app(
        analyze=_analyze,
        score=score_findings,
        report=_render_report,
        parse_report=_parse_report,
        evaluate_ml=_evaluate_ml,
        apply_advisory=_apply_advisory,
    )


def create_api(
    *,
    report_root: Path | None = None,
    data_root: Path | None = None,
    static_dir: Path | None = None,
    start_worker: bool = False,
) -> FastAPI:
    from securemail.adapters.persistence.job_store import FilesystemJobStore
    from securemail.adapters.persistence.report_repository import FilesystemReportRepository
    from securemail.adapters.reports.canonical_json import canonicalize, sha256_digest
    from securemail.adapters.reports.html_renderer import render_html
    from securemail.adapters.reports.pdf_renderer import render_pdf
    from securemail.api.dependencies import ApiDependencies
    from securemail.api.main import build_app
    from securemail.application.capture_intake import CaptureIntakeError, env_max_capture_bytes
    from securemail.domain.jobs.models import MAX_CAPTURE_BYTES

    unconfigured = Path("/securemail-unconfigured-report-root")
    configured_root = report_root
    if configured_root is None:
        env_root = os.environ.get("SECUREMAIL_REPORT_ROOT")
        configured_root = Path(env_root) if env_root else unconfigured
    configured_data = data_root
    if configured_data is None:
        env_data = os.environ.get("SECUREMAIL_DATA_ROOT")
        configured_data = Path(env_data) if env_data else configured_root
    configured_static = static_dir
    if configured_static is None:
        configured_static = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    job_store = None
    if configured_data != unconfigured:
        job_store = FilesystemJobStore(configured_data)
    try:
        max_capture_bytes = env_max_capture_bytes()
    except CaptureIntakeError:
        max_capture_bytes = MAX_CAPTURE_BYTES
    return build_app(
        ApiDependencies(
            report_repository=FilesystemReportRepository(configured_root),
            canonicalize=canonicalize,
            job_store=job_store,
            max_capture_bytes=max_capture_bytes,
            digest=sha256_digest,
            render_html=render_html,
            render_pdf=render_pdf,
        ),
        static_dir=configured_static,
        start_worker=start_worker,
        data_root=configured_data,
        report_root=configured_root,
    )


def main() -> None:
    create_cli()()
