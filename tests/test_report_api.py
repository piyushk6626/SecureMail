"""Step 11 FastAPI contract and security tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient
from pytest import MonkeyPatch
from tests.support.fixture_harness import repo_root
from typer.testing import CliRunner

from securemail.adapters.persistence.report_repository import FilesystemReportRepository
from securemail.adapters.reports.canonical_json import canonicalize
from securemail.api.dependencies import ApiDependencies
from securemail.api.main import build_app
from securemail.bootstrap import create_api, create_cli
from securemail.ports.persistence import MAX_REPORT_BYTES, ReportCatalogEntry

DASHBOARD_ROOT = repo_root() / "tests" / "fixtures" / "dashboard"


class _MemoryRepository:
    def __init__(self, reports: dict[str, bytes]) -> None:
        self._reports = reports

    def list_reports(self) -> tuple[ReportCatalogEntry, ...]:
        return tuple(
            ReportCatalogEntry(case_id=case_id, size_bytes=len(payload))
            for case_id, payload in self._reports.items()
        )

    def get_report(self, case_id: str) -> bytes | None:
        return self._reports.get(case_id)


def _client() -> TestClient:
    return TestClient(create_api(report_root=DASHBOARD_ROOT, static_dir=Path("/not-built")))


def test_health_and_cases_have_same_origin_security_headers() -> None:
    with _client() as client:
        health = client.get("/api/v1/health")
        cases = client.get("/api/v1/cases")
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert health.headers["cross-origin-opener-policy"] == "same-origin"
    assert health.headers["cross-origin-resource-policy"] == "same-origin"
    assert health.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in health.headers["content-security-policy"]
    assert cases.status_code == 200
    assert [item["case_id"] for item in cases.json()["cases"]] == [
        "dashboard_attention",
        "dashboard_clear",
        "dashboard_critical",
    ]


def test_api_report_bytes_exactly_equal_real_cli_json_output(tmp_path: Path) -> None:
    source = DASHBOARD_ROOT / "dashboard_critical.report.json"
    cli_out = tmp_path / "cli"
    result = CliRunner().invoke(
        create_cli(),
        ["report", str(source), "--format", "json", "--out", str(cli_out)],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    with _client() as client:
        response = client.get("/api/v1/cases/dashboard_critical/report")
    assert response.status_code == 200
    assert response.content == (cli_out / "report.json").read_bytes()
    assert response.headers["content-type"] == "application/json"


def test_preview_streams_and_returns_exact_canonical_bytes() -> None:
    raw = (DASHBOARD_ROOT / "dashboard_attention.report.json").read_bytes()
    with _client() as client:
        response = client.post(
            "/api/v1/reports/preview",
            content=raw,
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 200
    assert response.content == canonicalize(json.loads(raw))


def test_preview_rejects_invalid_and_oversized_reports() -> None:
    with _client() as client:
        invalid = client.post("/api/v1/reports/preview", content=b"{")
        oversized = client.post(
            "/api/v1/reports/preview",
            content=b"x" * (MAX_REPORT_BYTES + 1),
        )
    assert invalid.status_code == 400
    assert oversized.status_code == 413


def test_missing_mismatched_and_implicit_case_routes_are_not_visible() -> None:
    critical = (DASHBOARD_ROOT / "dashboard_critical.report.json").read_bytes()
    mismatch_app = build_app(
        ApiDependencies(
            report_repository=_MemoryRepository({"requested_case": critical}),
            canonicalize=canonicalize,
        )
    )
    with TestClient(mismatch_app) as mismatch_client:
        mismatch = mismatch_client.get("/api/v1/cases/requested_case/report")
    with _client() as client:
        missing = client.get("/api/v1/cases/missing/report")
        current = client.get("/api/v1/cases/current/report")
        latest = client.get("/api/v1/cases/latest/report")
        no_report_suffix = client.get("/api/v1/cases/dashboard_critical")
    assert mismatch.status_code == 404
    assert missing.status_code == 404
    assert current.status_code == 404
    assert latest.status_code == 404
    assert no_report_suffix.status_code == 404


def test_invalid_duplicate_catalog_is_a_typed_http_error(tmp_path: Path) -> None:
    (tmp_path / "one.json").write_bytes(b"{}")
    (tmp_path / "two.json").write_bytes(b"{}")
    (tmp_path / "catalog.json").write_text(
        json.dumps(
            {
                "schema_version": "securemail.report-catalog/v1",
                "reports": [
                    {"case_id": "duplicate", "report": "one.json"},
                    {"case_id": "duplicate", "report": "two.json"},
                ],
            }
        ),
        encoding="utf-8",
    )
    app = build_app(
        ApiDependencies(
            report_repository=FilesystemReportRepository(tmp_path),
            canonicalize=canonicalize,
        )
    )
    with TestClient(app) as client:
        response = client.get("/api/v1/cases")
    assert response.status_code == 503
    assert response.json() == {"detail": "report catalog unavailable"}


def test_environment_root_and_static_mount_preserve_api_routes(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECUREMAIL_REPORT_ROOT", str(DASHBOARD_ROOT))
    static_dir = tmp_path / "dist"
    static_dir.mkdir()
    (static_dir / "index.html").write_text("<main>dashboard</main>", encoding="utf-8")
    (static_dir / "asset.js").write_text("console.log(1);", encoding="utf-8")
    app = create_api(static_dir=static_dir)
    with TestClient(app) as client:
        health = client.get("/api/v1/health")
        frontend = client.get("/")
        cases = client.get("/cases")
        case_detail = client.get("/cases/dashboard_critical")
        upload = client.get("/upload")
        asset = client.get("/asset.js")
        missing_asset = client.get("/missing.js")
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert frontend.status_code == 200
    assert "dashboard" in frontend.text
    assert cases.status_code == 200
    assert "dashboard" in cases.text
    assert case_detail.status_code == 200
    assert "dashboard" in case_detail.text
    assert upload.status_code == 200
    assert "dashboard" in upload.text
    assert asset.status_code == 200
    assert asset.text == "console.log(1);"
    assert missing_asset.status_code == 404


def test_unconfigured_catalog_is_empty(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv("SECUREMAIL_REPORT_ROOT", raising=False)
    app = create_api(static_dir=Path("/not-built"))
    with TestClient(app) as client:
        response = client.get("/api/v1/cases")
    assert response.status_code == 200
    assert response.json() == {"cases": []}


def test_uvicorn_app_entrypoint_imports_in_a_fresh_interpreter() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "from securemail.api.main import app; app.url_path_for('health')",
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=repo_root(),
    )
    assert completed.returncode == 0, completed.stderr
