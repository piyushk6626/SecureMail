"""`securemail report` — render canonical JSON, HTML, and PDF from one object."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

import typer
from pydantic import ValidationError

from securemail.application.render_report import (
    RenderedReport,
    ReportError,
    parse_report_formats,
)
from securemail.domain.reports.schema import CanonicalReport

MAX_REPORT_INPUT_BYTES = 8 * 1024 * 1024


class ReportFn(Protocol):
    def __call__(self, report: CanonicalReport, *, formats: tuple[str, ...]) -> RenderedReport: ...


def register_report(app: typer.Typer, report: ReportFn) -> None:
    @app.command("report")
    def report_command(
        report_json: Path = typer.Argument(
            ...,
            exists=True,
            dir_okay=False,
            readable=True,
            help="Canonical report JSON (securemail.report/v1).",
        ),
        out: Path = typer.Option(..., "--out", help="Directory for report artifacts."),
        formats: str = typer.Option(
            "json,html,pdf",
            "--format",
            help="Comma-separated artifacts: json, html, pdf.",
        ),
    ) -> None:
        try:
            requested = parse_report_formats(formats)
            raw = report_json.read_bytes()
            if len(raw) > MAX_REPORT_INPUT_BYTES:
                raise ReportError(
                    f"report input exceeds {MAX_REPORT_INPUT_BYTES} bytes: {report_json}"
                )
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ReportError("report JSON must be an object")
            document = CanonicalReport.model_validate(payload)
            artifacts = report(document, formats=requested)
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValidationError,
            ReportError,
            ValueError,
        ) as exc:
            typer.secho(str(exc), err=True)
            raise typer.Exit(code=1) from exc

        out.mkdir(parents=True, exist_ok=True)
        if "json" in requested:
            json_path = out / "report.json"
            json_path.write_bytes(artifacts.json_bytes)
            (out / "report.json.sha256").write_text(
                f"{artifacts.sha256}  report.json\n",
                encoding="utf-8",
            )
        if "html" in requested:
            if artifacts.html is None:
                typer.secho("HTML artifact missing from renderer", err=True)
                raise typer.Exit(code=1)
            (out / "report.html").write_text(artifacts.html, encoding="utf-8")
        if "pdf" in requested:
            if artifacts.pdf is None:
                typer.secho("PDF artifact missing from renderer", err=True)
                raise typer.Exit(code=1)
            (out / "report.pdf").write_bytes(artifacts.pdf)
