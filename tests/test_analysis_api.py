"""Capture analysis HTTP API: intake, status, cancel, downloads."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from pytest import MonkeyPatch

from securemail.adapters.ml.baselines import BaselineAnomalyScorer
from securemail.adapters.persistence.job_store import FilesystemJobStore
from securemail.adapters.persistence.ml_history_store import FilesystemMlHistoryStore
from securemail.adapters.persistence.report_repository import FilesystemReportRepository
from securemail.adapters.persistence.writable_catalog import FilesystemCatalogPublisher
from securemail.adapters.reports.canonical_json import canonicalize, sha256_digest
from securemail.adapters.reports.html_renderer import render_html, renderer_manifest
from securemail.adapters.reports.pdf_renderer import render_pdf
from securemail.api.dependencies import ApiDependencies
from securemail.application.analysis_workflow import process_next_job
from securemail.application.run_analysis import PCAPNG_MAGIC
from securemail.application.stub_analyze import stub_analyze
from securemail.bootstrap import create_api
from securemail.domain.jobs.models import AnalysisStatus

PCAP_LE = b"\xd4\xc3\xb2\xa1"


def _app(tmp_path: Path) -> TestClient:
    return TestClient(
        create_api(
            report_root=tmp_path,
            data_root=tmp_path,
            static_dir=Path("/not-built"),
            start_worker=False,
        )
    )


def test_upload_rejects_non_pcap(tmp_path: Path) -> None:
    with _app(tmp_path) as client:
        response = client.post(
            "/api/v1/analyses",
            files={"file": ("note.json", b'{"a":1}', "application/json")},
        )
    assert response.status_code == 400


def test_upload_rejects_magic_mismatch(tmp_path: Path) -> None:
    with _app(tmp_path) as client:
        response = client.post(
            "/api/v1/analyses",
            files={
                "file": (
                    "mail.pcapng",
                    PCAP_LE + b"\x00\x01",
                    "application/octet-stream",
                )
            },
        )
    assert response.status_code == 400
    assert "PCAPNG magic" in response.json()["detail"]


def test_upload_and_status_then_cancel(tmp_path: Path) -> None:
    with _app(tmp_path) as client:
        created = client.post(
            "/api/v1/analyses",
            files={"file": ("mail.pcapng", PCAPNG_MAGIC + b"\x00\x01", "application/octet-stream")},
        )
        assert created.status_code == 202
        body = created.json()
        run_id = body["run_id"]
        assert body["status"] == "queued"
        status = client.get(f"/api/v1/analyses/{run_id}")
        assert status.status_code == 200
        assert status.json()["run_id"] == run_id
        missing = client.get("/api/v1/analyses/unknown-run")
        assert missing.status_code == 404
        cancel = client.post(f"/api/v1/analyses/{run_id}/cancel")
        assert cancel.status_code == 200
        assert cancel.json()["status"] == "cancelled"
        again = client.post(f"/api/v1/analyses/{run_id}/cancel")
        assert again.status_code == 409
        too_early = client.get(f"/api/v1/analyses/{run_id}/report")
        assert too_early.status_code == 409


def test_duplicate_upload_reuses_run(tmp_path: Path) -> None:
    payload = PCAPNG_MAGIC + b"\x11\x22"
    with _app(tmp_path) as client:
        first = client.post(
            "/api/v1/analyses",
            files={"file": ("mail.pcapng", payload, "application/octet-stream")},
        )
        second = client.post(
            "/api/v1/analyses",
            files={"file": ("mail.pcapng", payload, "application/octet-stream")},
        )
    assert first.status_code == 202
    assert second.status_code == 202
    assert first.json()["run_id"] == second.json()["run_id"]


def test_oversized_upload_is_413(tmp_path: Path) -> None:
    app = create_api(
        report_root=tmp_path,
        data_root=tmp_path,
        static_dir=Path("/not-built"),
        start_worker=False,
    )
    app.state.securemail_dependencies = ApiDependencies(
        report_repository=FilesystemReportRepository(tmp_path),
        canonicalize=canonicalize,
        job_store=FilesystemJobStore(tmp_path),
        max_capture_bytes=8,
        digest=sha256_digest,
        render_html=render_html,
        render_pdf=render_pdf,
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyses",
            files={
                "file": (
                    "mail.pcapng",
                    PCAPNG_MAGIC + b"\x00" * 32,
                    "application/octet-stream",
                )
            },
        )
    assert response.status_code == 413


def test_stub_pipeline_publishes_json_html_pdf(tmp_path: Path) -> None:
    with _app(tmp_path) as client:
        created = client.post(
            "/api/v1/analyses",
            files={"file": ("lab.pcapng", PCAPNG_MAGIC + b"\x00\x02", "application/octet-stream")},
        )
        run_id = created.json()["run_id"]
        case_id = created.json()["case_id"]
        store = FilesystemJobStore(tmp_path)
        renderer = renderer_manifest(pdf_renderer_version="69.0")
        process_next_job(
            job_store=store,
            history_store=FilesystemMlHistoryStore(tmp_path),
            catalog=FilesystemCatalogPublisher(tmp_path),
            analyze=stub_analyze,
            renderer=renderer,
            scorers=(BaselineAnomalyScorer(),),
            canonicalize=canonicalize,
            digest=sha256_digest,
            render_html=render_html,
            render_pdf=render_pdf,
            dependency_versions={"jinja2": "3.1.6", "weasyprint": "69.0"},
        )
        finished = client.get(f"/api/v1/analyses/{run_id}")
        assert finished.json()["status"] == AnalysisStatus.COMPLETED.value
        json_report = client.get(f"/api/v1/analyses/{run_id}/report")
        html = client.get(f"/api/v1/analyses/{run_id}/report.html")
        pdf = client.get(f"/api/v1/analyses/{run_id}/report.pdf")
        catalog = client.get(f"/api/v1/cases/{case_id}/report")
        assert json_report.status_code == 200
        assert html.status_code == 200
        assert pdf.status_code == 200
        assert catalog.status_code == 200
        assert catalog.content == json_report.content
        assert json_report.content == store.read_artifact(run_id, "report.json")
        disposition = html.headers["content-disposition"]
        assert "attachment" in disposition
        assert "../" not in disposition
        assert html.headers["content-type"].startswith("text/html")
        assert pdf.headers["content-type"] == "application/pdf"
        assert b"ADVISORY_INSUFFICIENT_HISTORY" in json_report.content
        case_html = client.get(f"/api/v1/cases/{case_id}/report.html")
        assert case_html.status_code == 200


def test_unconfigured_analysis_is_unavailable(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv("SECUREMAIL_DATA_ROOT", raising=False)
    monkeypatch.delenv("SECUREMAIL_REPORT_ROOT", raising=False)
    app = create_api(static_dir=Path("/not-built"), start_worker=False)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyses",
            files={"file": ("mail.pcapng", PCAPNG_MAGIC + b"\x00", "application/octet-stream")},
        )
    assert response.status_code == 503
