"""`securemail evaluate-ml` — evaluation harness over a seeded cohort directory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

import typer
from pydantic import ValidationError

from securemail.application.advisory_pipeline import AdvisoryPipelineError
from securemail.domain.ml.models import EvaluationReport


class EvaluateMlFn(Protocol):
    def __call__(self, cohort_dir: Path) -> EvaluationReport: ...


def register_evaluate_ml(app: typer.Typer, evaluate_ml: EvaluateMlFn) -> None:
    @app.command("evaluate-ml")
    def evaluate_ml_command(
        cohort_dir: Path = typer.Argument(
            ...,
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            help="Seeded cohort directory (manifest.json, labels.json, windows.json).",
        ),
    ) -> None:
        try:
            report = evaluate_ml(cohort_dir)
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValidationError,
            AdvisoryPipelineError,
            ValueError,
        ) as exc:
            typer.secho(str(exc), err=True)
            raise typer.Exit(code=1) from exc
        typer.echo(
            json.dumps(
                report.model_dump(mode="json"),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
        )
        if not report.gates.all_passed:
            raise typer.Exit(code=1)
