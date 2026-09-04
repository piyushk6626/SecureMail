"""Composition root: the only module that imports a port and its adapter."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import typer

from securemail.adapters.analyzers.capinfos_runner import DockerCapinfosRunner
from securemail.adapters.analyzers.tshark_runner import DockerTSharkRunner
from securemail.adapters.analyzers.zeek_runner import DockerZeekRunner
from securemail.adapters.artifacts.certificate_store import CertificateStore
from securemail.adapters.reference_data.iana_tls_parameters import load_iana_tls_parameters
from securemail.application.run_analysis import (
    DEFAULT_EXPIRY_WARNING_SECONDS,
    AnalyzeRequest,
    run_analysis,
)
from securemail.domain.evidence.run import EvidenceDocument


def _analyze(
    capture: Path,
    *,
    artifact_root: Path | None = None,
    analysis_time: datetime | None = None,
    expiry_warning_seconds: int = DEFAULT_EXPIRY_WARNING_SECONDS,
) -> EvidenceDocument:
    store = CertificateStore(root=artifact_root)
    return run_analysis(
        AnalyzeRequest(
            capture_path=capture,
            analysis_time=analysis_time,
            expiry_warning_seconds=expiry_warning_seconds,
        ),
        zeek_runner=DockerZeekRunner(),
        preflight_runner=DockerCapinfosRunner(),
        tshark_runner=DockerTSharkRunner(),
        tls_parameters=load_iana_tls_parameters(),
        artifact_store=store,
    )


def create_cli() -> typer.Typer:
    from securemail.api.cli.main import build_app

    return build_app(analyze=_analyze)


def main() -> None:
    create_cli()()
