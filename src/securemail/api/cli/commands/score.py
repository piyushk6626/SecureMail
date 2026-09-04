"""`securemail score` — thin CLI over the scoring use case."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

import typer
from pydantic import ValidationError

from securemail.application.run_analysis import ScoreRequest
from securemail.domain.findings.posture import PostureAssessment

MAX_SCORE_INPUT_BYTES = 8 * 1024 * 1024


class ScoreFn(Protocol):
    def __call__(self, request: ScoreRequest) -> PostureAssessment: ...


def register_score(app: typer.Typer, score: ScoreFn) -> None:
    @app.command("score")
    def score_command(
        findings_json: Path = typer.Argument(
            ...,
            exists=True,
            dir_okay=False,
            readable=True,
            help="Synthetic findings JSON (securemail.score_request/v1).",
        ),
    ) -> None:
        try:
            raw = findings_json.read_bytes()
            if len(raw) > MAX_SCORE_INPUT_BYTES:
                raise ValueError(
                    f"score input exceeds {MAX_SCORE_INPUT_BYTES} bytes: {findings_json}"
                )
            payload = json.loads(raw.decode("utf-8"))
            request = ScoreRequest.model_validate(payload)
            assessment = score(request)
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValidationError,
            ValueError,
        ) as exc:
            typer.secho(str(exc), err=True)
            raise typer.Exit(code=1) from exc
        typer.echo(
            json.dumps(
                assessment.model_dump(mode="json"),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
        )
