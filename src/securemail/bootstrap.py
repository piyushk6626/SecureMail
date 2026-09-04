"""Composition root: the only module that imports a port and its adapter."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import typer

from securemail.adapters.analyzers.capinfos_runner import DockerCapinfosRunner
from securemail.adapters.analyzers.tshark_runner import DockerTSharkRunner
from securemail.adapters.analyzers.zeek_runner import DockerZeekRunner
from securemail.adapters.artifacts.certificate_store import CertificateStore
from securemail.adapters.ml.baselines import BaselineAnomalyScorer
from securemail.adapters.ml.isolation_forest import IsolationForestScorer
from securemail.adapters.pki.trust_store import load_trust_store_snapshot
from securemail.adapters.reference_data.iana_tls_parameters import load_iana_tls_parameters
from securemail.adapters.reference_data.policy_packs import PolicyPackError, load_policy_pack
from securemail.application.advisory_pipeline import attach_advisories, evaluate_cohort_dir
from securemail.application.render_report import RenderedReport, render_report
from securemail.application.run_analysis import (
    DEFAULT_EXPIRY_WARNING_SECONDS,
    AnalysisError,
    AnalyzeRequest,
    run_analysis,
    score_findings,
)
from securemail.domain.evidence.run import EvidenceDocument, PolicyProfile
from securemail.domain.ml.models import EvaluationReport
from securemail.domain.reports.schema import CanonicalReport


def _analyze(
    capture: Path,
    *,
    artifact_root: Path | None = None,
    analysis_time: datetime | None = None,
    expiry_warning_seconds: int = DEFAULT_EXPIRY_WARNING_SECONDS,
    expected_hostname: str | None = None,
    policy_profile: PolicyProfile = PolicyProfile.IETF_CURRENT,
) -> EvidenceDocument:
    store = CertificateStore(root=artifact_root)
    try:
        policy_pack, policy_pack_digest = load_policy_pack(policy_profile)
    except PolicyPackError as exc:
        raise AnalysisError(str(exc)) from exc
    return run_analysis(
        AnalyzeRequest(
            capture_path=capture,
            analysis_time=analysis_time,
            expiry_warning_seconds=expiry_warning_seconds,
            expected_hostname=expected_hostname,
            policy_profile=policy_profile,
        ),
        zeek_runner=DockerZeekRunner(),
        preflight_runner=DockerCapinfosRunner(),
        tshark_runner=DockerTSharkRunner(),
        tls_parameters=load_iana_tls_parameters(),
        artifact_store=store,
        trust_snapshot=load_trust_store_snapshot(),
        policy_pack=policy_pack,
        policy_pack_digest=policy_pack_digest,
    )


def _render_report(report: CanonicalReport, *, formats: tuple[str, ...]) -> RenderedReport:
    from securemail.adapters.reports.canonical_json import canonicalize, sha256_digest
    from securemail.adapters.reports.html_renderer import render_html
    from securemail.adapters.reports.pdf_renderer import render_pdf

    return render_report(
        report,
        formats,
        canonicalize=canonicalize,
        digest=sha256_digest,
        render_html=render_html,
        render_pdf=render_pdf,
    )


def _evaluate_ml(cohort_dir: Path) -> EvaluationReport:
    return evaluate_cohort_dir(
        cohort_dir,
        baseline=BaselineAnomalyScorer(),
        challenger=IsolationForestScorer(),
    )


def _apply_advisory(report: CanonicalReport) -> CanonicalReport:
    return attach_advisories(
        report,
        scorers=(BaselineAnomalyScorer(), IsolationForestScorer()),
        cohort="capture",
    )


def create_cli() -> typer.Typer:
    from securemail.api.cli.main import build_app

    return build_app(
        analyze=_analyze,
        score=score_findings,
        report=_render_report,
        evaluate_ml=_evaluate_ml,
        apply_advisory=_apply_advisory,
    )


def main() -> None:
    create_cli()()
