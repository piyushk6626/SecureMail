"""`securemail report` — render canonical JSON, HTML, and PDF from one object."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

import typer

from securemail.application.advisory_pipeline import AdvisoryPipelineError
from securemail.application.render_report import (
    RenderedReport,
    ReportError,
    parse_report_formats,
)
from securemail.application.report_queries import (
    ParsedReport,
    ParseReportRequest,
    ReportQueryError,
)
from securemail.domain.reports.schema import CanonicalReport
from securemail.ports.persistence import MAX_REPORT_BYTES

MAX_REPORT_INPUT_BYTES = MAX_REPORT_BYTES


class ReportFn(Protocol):
    def __call__(self, report: CanonicalReport, *, formats: tuple[str, ...]) -> RenderedReport: ...


class ApplyAdvisoryFn(Protocol):
    def __call__(self, report: CanonicalReport) -> CanonicalReport: ...


class ParseReportFn(Protocol):
    def __call__(self, request: ParseReportRequest) -> ParsedReport: ...


def register_report(
    app: typer.Typer,
    report: ReportFn,
    parse: ParseReportFn,
    apply_advisory: ApplyAdvisoryFn,
) -> None:
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
        advisory: bool = typer.Option(
            False,
            "--advisory",
            help="Run shadow-mode ML after deterministic findings. Off by default.",
        ),
    ) -> None:
        try:
            requested = parse_report_formats(formats)
            raw = report_json.read_bytes()
            document = parse(ParseReportRequest(report_bytes=raw)).report
            if advisory:
                document = apply_advisory(document)
            artifacts = report(document, formats=requested)
        except (
            OSError,
            ReportQueryError,
            ReportError,
            AdvisoryPipelineError,
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
