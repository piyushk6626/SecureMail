"""Composition root: the only module that imports a port and its adapter."""

from __future__ import annotations

from pathlib import Path

import typer

from securemail.adapters.analyzers.zeek_runner import DockerZeekRunner
from securemail.application.run_analysis import AnalyzeRequest, run_analysis
from securemail.domain.evidence.run import EvidenceDocument


def _analyze(capture: Path) -> EvidenceDocument:
    runner = DockerZeekRunner()
    return run_analysis(AnalyzeRequest(capture_path=capture), zeek_runner=runner)


def create_cli() -> typer.Typer:
    from securemail.api.cli.main import build_app

    return build_app(analyze=_analyze)


def main() -> None:
    create_cli()()
