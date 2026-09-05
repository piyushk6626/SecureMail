"""Worker pipeline failure and publication paths."""

from __future__ import annotations

import json
from pathlib import Path

from securemail.adapters.ml.baselines import BaselineAnomalyScorer
from securemail.adapters.persistence.job_store import FilesystemJobStore
from securemail.adapters.persistence.ml_history_store import FilesystemMlHistoryStore
from securemail.adapters.persistence.writable_catalog import FilesystemCatalogPublisher
from securemail.adapters.reports.canonical_json import canonicalize, sha256_digest
from securemail.adapters.reports.html_renderer import render_html, renderer_manifest
from securemail.adapters.reports.pdf_renderer import render_pdf
from securemail.application.analysis_workflow import AnalyzeFn, process_next_job
from securemail.application.capture_intake import CaptureIntakeRequest, ingest_capture
from securemail.application.run_analysis import PCAPNG_MAGIC, AnalysisError, AnalyzeRequest
from securemail.application.stub_analyze import stub_analyze
from securemail.domain.evidence.run import EvidenceDocument
from securemail.domain.jobs.models import AnalysisStatus


def _process(
    tmp_path: Path,
    *,
    analyze: AnalyzeFn,
) -> None:
    process_next_job(
        job_store=FilesystemJobStore(tmp_path),
        history_store=FilesystemMlHistoryStore(tmp_path),
        catalog=FilesystemCatalogPublisher(tmp_path),
        analyze=analyze,
        renderer=renderer_manifest(pdf_renderer_version="69.0"),
        scorers=(BaselineAnomalyScorer(),),
        canonicalize=canonicalize,
        digest=sha256_digest,
        render_html=render_html,
        render_pdf=render_pdf,
        dependency_versions={"jinja2": "3.1.6", "weasyprint": "69.0"},
    )


def test_analyzer_failure_marks_job_failed(tmp_path: Path) -> None:
    store = FilesystemJobStore(tmp_path)
    job = ingest_capture(
        CaptureIntakeRequest(original_filename="mail.pcapng"),
        iter([PCAPNG_MAGIC, b"\x00"]),
        job_store=store,
    )

    def boom(_request: AnalyzeRequest) -> EvidenceDocument:
        raise AnalysisError("zeek failed")

    _process(tmp_path, analyze=boom)
    failed = store.get_job(job.run_id)
    assert failed is not None
    assert failed.status is AnalysisStatus.FAILED
    assert failed.error_message == "zeek failed"


def test_stub_job_publishes_catalog_without_mutating_findings(tmp_path: Path) -> None:
    store = FilesystemJobStore(tmp_path)
    job = ingest_capture(
        CaptureIntakeRequest(original_filename="mail.pcapng"),
        iter([PCAPNG_MAGIC, b"\x00"]),
        job_store=store,
    )
    _process(tmp_path, analyze=stub_analyze)
    finished = store.get_job(job.run_id)
    assert finished is not None
    assert finished.status is AnalysisStatus.COMPLETED
    catalog = tmp_path / f"{job.case_id}.report.json"
    assert catalog.is_file()
    payload = json.loads(catalog.read_text(encoding="utf-8"))
    assert payload["evidence"]["findings"] == []
    codes = [item["code"] for item in payload["advisory"]["items"]]
    assert "ADVISORY_INSUFFICIENT_HISTORY" in codes
