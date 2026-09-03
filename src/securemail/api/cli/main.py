"""Typer CLI entry point. Wired through bootstrap; does not import adapters."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import typer

from securemail.application.run_analysis import AnalysisError, InvalidCaptureError
from securemail.domain.evidence.run import EvidenceDocument

AnalyzeFn = Callable[[Path], EvidenceDocument]


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
    ) -> None:
        try:
            document = analyze(capture)
        except (AnalysisError, InvalidCaptureError, FileNotFoundError, OSError) as exc:
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
