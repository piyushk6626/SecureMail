"""Step 9 golden report through the real `securemail report` CLI."""

from __future__ import annotations

import json
from pathlib import Path

from tests.support.fixture_harness import load_golden_report, repo_root
from typer.testing import CliRunner

from securemail.adapters.reports.canonical_json import canonicalize, sha256_digest
from securemail.adapters.reports.html_renderer import render_html
from securemail.adapters.reports.pdf_renderer import render_pdf
from securemail.api.cli.commands.report import MAX_REPORT_INPUT_BYTES
from securemail.application.render_report import parse_report_formats, render_report
from securemail.bootstrap import create_cli
from securemail.domain.reports.schema import CanonicalReport


def _provenance() -> dict[str, object]:
    path = repo_root() / "tests" / "fixtures" / "reports" / "provenance.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_report_help_lists_command() -> None:
    result = CliRunner().invoke(create_cli(), ["--help"])
    assert result.exit_code == 0
    assert "report" in result.output


def test_cli_writes_json_html_pdf(tmp_path: Path) -> None:
    golden = repo_root() / "tests" / "fixtures" / "reports" / "golden_report.json"
    result = CliRunner().invoke(
        create_cli(),
        ["report", str(golden), "--format", "json,html,pdf", "--out", str(tmp_path)],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    pdf_path = tmp_path / "report.pdf"
    sidecar = tmp_path / "report.json.sha256"
    assert json_path.is_file()
    assert html_path.is_file()
    assert pdf_path.is_file()
    assert sidecar.is_file()
    canonical = json_path.read_bytes()
    assert canonical == canonicalize(load_golden_report())
    digest = sha256_digest(canonical)
    assert digest == _provenance()["canonical_json_sha256"]
    assert sidecar.read_text(encoding="utf-8").startswith(digest)


def test_html_and_pdf_share_one_in_memory_object() -> None:
    report = CanonicalReport.model_validate(load_golden_report())
    artifacts = render_report(
        report,
        ("json", "html", "pdf"),
        canonicalize=canonicalize,
        digest=sha256_digest,
        render_html=render_html,
        render_pdf=render_pdf,
    )
    assert artifacts.html is not None
    assert artifacts.pdf is not None
    assert artifacts.html == render_html(artifacts.payload)
    assert artifacts.pdf == render_pdf(artifacts.html)
    codes = _provenance()["finding_codes"]
    assert isinstance(codes, list)
    from io import BytesIO

    from pypdf import PdfReader

    pdf_text = "\n".join(
        page.extract_text() or "" for page in PdfReader(BytesIO(artifacts.pdf)).pages
    )
    for code in codes:
        token = str(code)
        assert token in json.dumps(artifacts.payload)
        assert token in artifacts.html
        assert token in pdf_text


def test_parse_report_formats_rejects_unknown() -> None:
    import pytest

    from securemail.application.render_report import ReportError

    with pytest.raises(ReportError):
        parse_report_formats("json,exe")


def test_report_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{", encoding="utf-8")
    result = CliRunner().invoke(create_cli(), ["report", str(path), "--out", str(tmp_path / "out")])
    assert result.exit_code == 1


def test_report_rejects_unknown_fields(tmp_path: Path) -> None:
    path = tmp_path / "extra.json"
    path.write_text(
        json.dumps({"schema_version": "securemail.report/v1", "unexpected": True}),
        encoding="utf-8",
    )
    result = CliRunner().invoke(create_cli(), ["report", str(path), "--out", str(tmp_path / "out")])
    assert result.exit_code == 1


def test_report_rejects_oversized_input(tmp_path: Path) -> None:
    path = tmp_path / "huge.json"
    path.write_bytes(b"{" + b"a" * (MAX_REPORT_INPUT_BYTES + 1))
    result = CliRunner().invoke(create_cli(), ["report", str(path), "--out", str(tmp_path / "out")])
    assert result.exit_code == 1


def test_report_missing_file_exits_2(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        create_cli(),
        ["report", str(tmp_path / "missing.json"), "--out", str(tmp_path / "out")],
    )
    assert result.exit_code == 2
