"""Typer CLI entry point. Wired through bootstrap; does not import adapters."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

import typer

from securemail.application.run_analysis import (
    DEFAULT_EXPIRY_WARNING_SECONDS,
    AnalysisError,
    InvalidCaptureError,
)
from securemail.domain.evidence.run import EvidenceDocument


class AnalyzeFn(Protocol):
    def __call__(
        self,
        capture: Path,
        *,
        artifact_root: Path | None = None,
        analysis_time: datetime | None = None,
        expiry_warning_seconds: int = DEFAULT_EXPIRY_WARNING_SECONDS,
        expected_hostname: str | None = None,
    ) -> EvidenceDocument: ...


def parse_analysis_time(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def build_app(analyze: AnalyzeFn) -> typer.Typer:
    app = typer.Typer(no_args_is_help=True, add_completion=False)

    @app.callback()
    def _root() -> None:
        """SecureMail: offline SMTP/IMAP/POP3 cryptographic posture analysis."""

    register_analyze(app, analyze)
    return app


def register_analyze(app: typer.Typer, analyze: AnalyzeFn) -> None:
    @app.command("analyze")
    def analyze_command(
        capture: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
        out: Path = typer.Option(..., "--out", help="Canonical JSON output path"),
        analysis_time: str | None = typer.Option(
            None,
            "--analysis-time",
            help="UTC instant for valid_at_analysis_time (RFC 3339). Default: now.",
        ),
        expiry_warning_days: int = typer.Option(
            30,
            "--expiry-warning-days",
            min=1,
            help="Warning window in days for expires_within_warning_window.",
        ),
        expected_hostname: str | None = typer.Option(
            None,
            "--expected-hostname",
            help="Configured reference identity for SAN matching. Default: observed SNI.",
        ),
    ) -> None:
        try:
            parsed_time = parse_analysis_time(analysis_time) if analysis_time else None
            document = analyze(
                capture,
                artifact_root=out.parent / "certificates",
                analysis_time=parsed_time,
                expiry_warning_seconds=expiry_warning_days * 24 * 60 * 60,
                expected_hostname=expected_hostname,
            )
        except (AnalysisError, InvalidCaptureError, FileNotFoundError, OSError, ValueError) as exc:
            typer.secho(str(exc), err=True)
            raise typer.Exit(code=1) from exc
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = document.model_dump(mode="json")
        out.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


def main() -> None:
    from securemail.bootstrap import create_cli

    create_cli()()
