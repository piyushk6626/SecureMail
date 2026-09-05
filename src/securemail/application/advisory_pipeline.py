"""Advisory ML orchestration. Runs after deterministic analysis; never edits findings."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from securemail.domain.evidence.certificate import CertificateEvidence, CertificateRole
from securemail.domain.evidence.flow import Flow, ReconstructionQuality
from securemail.domain.evidence.handshake import TlsHandshake
from securemail.domain.evidence.run import EvidenceDocument, EvidenceState
from securemail.domain.evidence.session import EmailSession, MailProtocol, UpgradeState
from securemail.domain.ml.evaluation import (
    INCOMPLETE_RATE_GATE,
    ISOLATION_FOREST_MIN_TRAIN_WINDOWS,
    MIN_HISTORY_WINDOWS,
    compare_detectors,
)
from securemail.domain.ml.models import (
    FEATURE_SCHEMA_VERSION,
    AnomalyResult,
    CohortLabels,
    CohortManifest,
    EndpointWindow,
    EvaluationReport,
    ProtocolRole,
    WindowScore,
)
from securemail.domain.policies.tls.forward_secrecy import (
    ForwardSecrecyOutcome,
    assess_forward_secrecy,
)
from securemail.domain.reports.schema import AdvisoryItem, AdvisorySection, CanonicalReport
from securemail.ports.ml import AnomalyScorer, MlDependencyError

_ADVISORY_NONE_CODE = "ADVISORY_NONE"
_ADVISORY_INSUFFICIENT_HISTORY_CODE = "ADVISORY_INSUFFICIENT_HISTORY"
_CODE_FOR_FEATURE = {
    "tls10_share": "ADVISORY_TLS_VERSION_SHIFT",
    "tls12_share": "ADVISORY_TLS_VERSION_SHIFT",
    "tls13_share": "ADVISORY_TLS_VERSION_SHIFT",
    "dominant_tls_version": "ADVISORY_TLS_VERSION_SHIFT",
    "handshake_failure_rate": "ADVISORY_HANDSHAKE_FAILURE_RATE",
    "alert_rate": "ADVISORY_ALERT_RATE",
    "starttls_fallback_rate": "ADVISORY_STARTTLS_FALLBACK_RATE",
    "starttls_success_rate": "ADVISORY_STARTTLS_FALLBACK_RATE",
    "forward_secrecy_present_rate": "ADVISORY_FORWARD_SECRECY_RATE",
    "issuer_id": "ADVISORY_CERTIFICATE_ISSUER",
    "certificate_churn_rate": "ADVISORY_CERTIFICATE_ISSUER",
}


class AdvisoryPipelineError(Exception):
    """Raised when advisory scoring cannot complete."""


def _opaque_issuer(raw: str | None) -> str:
    if not raw:
        return "iss_unknown"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"iss_{digest}"


def _role_for(session: EmailSession, flow: Flow | None) -> ProtocolRole:
    port = flow.resp.port if flow is not None else None
    if port == 25:
        return ProtocolRole.SMTP_MX
    if port in {465, 587}:
        return ProtocolRole.SMTP_SUBMISSION
    if port in {143, 993}:
        return ProtocolRole.IMAP_ACCESS
    if port in {110, 995}:
        return ProtocolRole.POP3_ACCESS
    if session.protocol is MailProtocol.SMTP:
        return ProtocolRole.SMTP_MX
    if session.protocol is MailProtocol.IMAP:
        return ProtocolRole.IMAP_ACCESS
    if session.protocol is MailProtocol.POP3:
        return ProtocolRole.POP3_ACCESS
    return ProtocolRole.SMTP_MX


def _mean(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def extract_endpoint_windows(document: EvidenceDocument) -> list[EndpointWindow]:
    """Build one capture-level window per responder endpoint from canonical evidence."""

    flows = {flow.uid: flow for flow in document.flows}
    handshakes = {item.uid: item for item in document.handshakes}
    certificates: dict[str, list[CertificateEvidence]] = defaultdict(list)
    for cert in document.certificates:
        certificates[cert.uid].append(cert)

    grouped: dict[str, list[tuple[EmailSession, Flow | None, TlsHandshake | None]]] = defaultdict(
        list
    )
    for session in document.sessions:
        flow = flows.get(session.uid)
        endpoint = (
            f"{flow.resp.host}:{flow.resp.port}" if flow is not None else f"session:{session.uid}"
        )
        grouped[endpoint].append((session, flow, handshakes.get(session.uid)))

    windows: list[EndpointWindow] = []
    for endpoint_id, rows in sorted(grouped.items()):
        tls13 = 0
        tls12 = 0
        tls10 = 0
        versioned = 0
        failures = 0
        alerts = 0
        hs_count = 0
        starttls_ok = 0
        starttls_fallback = 0
        starttls_n = 0
        fs_present = 0
        fs_n = 0
        incomplete = 0
        not_obs = 0
        flow_n = 0
        issuers: list[str] = []
        role = ProtocolRole.SMTP_MX
        for session, flow, handshake in rows:
            role = _role_for(session, flow)
            if flow is not None:
                flow_n += 1
                if flow.reconstruction_quality is ReconstructionQuality.INCOMPLETE:
                    incomplete += 1
            if session.explicit_upgrade is not None and session.explicit_upgrade.state is not None:
                starttls_n += 1
                if session.explicit_upgrade.state is UpgradeState.PLAINTEXT_FALLBACK:
                    starttls_fallback += 1
                if session.explicit_upgrade.state in {
                    UpgradeState.TLS_ESTABLISHED,
                    UpgradeState.ACCEPTED,
                }:
                    starttls_ok += 1
            if handshake is None:
                continue
            hs_count += 1
            if not handshake.established:
                failures += 1
            if handshake.last_alert:
                alerts += 1
            if handshake.server_certificate_state is EvidenceState.NOT_OBSERVABLE:
                not_obs += 1
            selected = handshake.version.selected
            if selected:
                versioned += 1
                if selected == "TLSv13":
                    tls13 += 1
                elif selected == "TLSv12":
                    tls12 += 1
                elif selected in {"TLSv10", "TLSv11", "SSLv3"}:
                    tls10 += 1
            assessment = assess_forward_secrecy(handshake)
            fs_n += 1
            if assessment.outcome is ForwardSecrecyOutcome.PRESENT:
                fs_present += 1
            leaves = [
                cert
                for cert in certificates.get(session.uid, [])
                if cert.chain_index == 0 and cert.role is CertificateRole.SERVER
            ]
            if leaves:
                issuers.append(_opaque_issuer(leaves[0].issuer))
        dominant = "TLSv13"
        if versioned:
            if tls10 >= tls13 and tls10 >= tls12:
                dominant = "TLSv10"
            elif tls12 > tls13:
                dominant = "TLSv12"
        issuer_id = issuers[0] if issuers else "iss_unknown"
        unique_issuers = len(set(issuers))
        churn = 0.0 if unique_issuers <= 1 else 1.0
        incomplete_rate = _mean([1.0] * incomplete + [0.0] * max(flow_n - incomplete, 0))
        windows.append(
            EndpointWindow(
                endpoint_id=endpoint_id,
                site_id="capture",
                protocol_role=role,
                day_index=0,
                session_count=len(rows),
                tls13_share=_mean([1.0] * tls13 + [0.0] * max(versioned - tls13, 0)),
                tls12_share=_mean([1.0] * tls12 + [0.0] * max(versioned - tls12, 0)),
                tls10_share=_mean([1.0] * tls10 + [0.0] * max(versioned - tls10, 0)),
                handshake_failure_rate=_mean(
                    [1.0] * failures + [0.0] * max(hs_count - failures, 0)
                ),
                alert_rate=_mean([1.0] * alerts + [0.0] * max(hs_count - alerts, 0)),
                starttls_success_rate=_mean(
                    [1.0] * starttls_ok + [0.0] * max(starttls_n - starttls_ok, 0)
                ),
                starttls_fallback_rate=_mean(
                    [1.0] * starttls_fallback + [0.0] * max(starttls_n - starttls_fallback, 0)
                ),
                forward_secrecy_present_rate=_mean(
                    [1.0] * fs_present + [0.0] * max(fs_n - fs_present, 0)
                ),
                certificate_churn_rate=churn,
                incomplete_reconstruction_rate=incomplete_rate,
                not_observable_rate=_mean([1.0] * not_obs + [0.0] * max(hs_count - not_obs, 0)),
                dominant_tls_version=dominant,
                issuer_id=issuer_id,
                in_maintenance=False,
                is_new_endpoint=True,
                capture_quality_ok=incomplete_rate <= INCOMPLETE_RATE_GATE,
            )
        )
    return windows


def _anomaly_id(score: WindowScore) -> str:
    payload = "|".join(
        (
            score.endpoint_id,
            str(score.day_index),
            score.detector,
            score.model_digest,
            score.reason,
        )
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _code_for(score: WindowScore) -> str:
    if not score.contributions:
        return "ADVISORY_MULTIVARIATE_DEVIATION"
    feature = score.contributions[0].feature
    if score.detector == "isolation_forest" and len(score.contributions) > 1:
        return "ADVISORY_MULTIVARIATE_DEVIATION"
    return _CODE_FOR_FEATURE.get(feature, "ADVISORY_MULTIVARIATE_DEVIATION")


def anomalies_from_scores(
    scores: Sequence[WindowScore],
    *,
    cohort: str,
) -> list[AnomalyResult]:
    results: list[AnomalyResult] = []
    seen: set[str] = set()
    ordered = sorted(
        (
            item
            for item in scores
            if item.above_threshold and not item.suppressed and item.skip_reason is None
        ),
        key=lambda item: (-item.score, item.endpoint_id, item.day_index),
    )
    for item in ordered:
        key = f"{item.endpoint_id}:{item.detector}"
        if key in seen:
            continue
        seen.add(key)
        fields = [contrib.evidence_field for contrib in item.contributions]
        results.append(
            AnomalyResult(
                anomaly_id=_anomaly_id(item),
                code=_code_for(item),
                label="advisory_anomaly",
                detector=item.detector,
                score=item.score,
                threshold=item.threshold,
                percentile=item.percentile,
                cohort=cohort,
                feature_schema_version=item.feature_schema_version,
                model_digest=item.model_digest,
                endpoint_id=item.endpoint_id,
                day_index=item.day_index,
                reason=item.reason,
                reason_codes=[contrib.feature for contrib in item.contributions],
                evidence_fields=fields,
            )
        )
    return results


def advisory_section_from_results(results: Sequence[AnomalyResult]) -> AdvisorySection:
    if not results:
        return AdvisorySection(
            present=True,
            items=[
                AdvisoryItem(
                    code=_ADVISORY_NONE_CODE,
                    reason=(
                        "Advisory scoring ran; no endpoint-window deviation met the review "
                        "threshold. Deterministic findings are unchanged. field session.uid."
                    ),
                )
            ],
        )
    items = [AdvisoryItem(code=item.code, reason=item.reason) for item in results[:256]]
    return AdvisorySection(present=True, items=items)


def _assign_day_index(
    windows: Sequence[EndpointWindow],
    *,
    day_index: int,
) -> list[EndpointWindow]:
    return [
        window.model_copy(
            update={
                "day_index": day_index,
                "site_id": "local",
                "is_new_endpoint": day_index == 0,
            }
        )
        for window in windows
    ]


def advisory_section_for_history(
    *,
    history_count: int,
    current_scores: Sequence[WindowScore],
    cohort: str,
) -> AdvisorySection:
    items: list[AdvisoryItem] = []
    if history_count < MIN_HISTORY_WINDOWS:
        items.append(
            AdvisoryItem(
                code=_ADVISORY_INSUFFICIENT_HISTORY_CODE,
                reason=(
                    f"Local ML history has {history_count} endpoint-windows; "
                    f"baseline needs {MIN_HISTORY_WINDOWS} and Isolation Forest needs "
                    f"{ISOLATION_FOREST_MIN_TRAIN_WINDOWS}. Deterministic findings are "
                    "unchanged. field session.uid."
                ),
            )
        )
        return AdvisorySection(present=True, items=items)
    if history_count < ISOLATION_FOREST_MIN_TRAIN_WINDOWS:
        items.append(
            AdvisoryItem(
                code=_ADVISORY_INSUFFICIENT_HISTORY_CODE,
                reason=(
                    f"Isolation Forest needs {ISOLATION_FOREST_MIN_TRAIN_WINDOWS} training "
                    f"windows; {history_count} are stored. Baseline scoring ran. "
                    "Deterministic findings are unchanged. field session.uid."
                ),
            )
        )
    anomalies = anomalies_from_scores(current_scores, cohort=cohort)
    if anomalies:
        items.extend(AdvisoryItem(code=item.code, reason=item.reason) for item in anomalies)
    elif not items:
        return advisory_section_from_results(())
    return AdvisorySection(present=True, items=items[:256])


def attach_advisories_with_history(
    report: CanonicalReport,
    *,
    scorers: Sequence[AnomalyScorer],
    history: Sequence[EndpointWindow],
    cohort: str = "local",
) -> tuple[CanonicalReport, list[EndpointWindow]]:
    """Score current windows against persisted history. Never edits findings."""

    evidence = report.evidence
    extracted = extract_endpoint_windows(evidence)
    next_day = 0
    if history:
        next_day = max(item.day_index for item in history) + 1
    current = _assign_day_index(extracted, day_index=next_day)
    combined = [*history, *current]
    scores = score_windows(combined, scorers)
    current_scores = [item for item in scores if item.day_index == next_day]
    updated = report.model_copy(
        update={
            "advisory": advisory_section_for_history(
                history_count=len(history),
                current_scores=current_scores,
                cohort=cohort,
            )
        }
    )
    if updated.evidence is not evidence:
        raise AdvisoryPipelineError("advisory pipeline mutated canonical evidence")
    if updated.evidence.findings is not evidence.findings:
        raise AdvisoryPipelineError("advisory pipeline mutated deterministic findings")
    return updated, current


def score_windows(
    windows: Sequence[EndpointWindow],
    scorers: Sequence[AnomalyScorer],
) -> list[WindowScore]:
    merged: list[WindowScore] = []
    try:
        for scorer in scorers:
            merged.extend(scorer.score_windows(windows))
    except MlDependencyError as exc:
        raise AdvisoryPipelineError(str(exc)) from exc
    return merged


def attach_advisories(
    report: CanonicalReport,
    *,
    scorers: Sequence[AnomalyScorer],
    cohort: str = "capture",
) -> CanonicalReport:
    """Return a new report with advisories. The nested evidence object is unchanged."""

    evidence = report.evidence
    windows = extract_endpoint_windows(evidence)
    scores = score_windows(windows, scorers)
    results = anomalies_from_scores(scores, cohort=cohort)
    updated = report.model_copy(update={"advisory": advisory_section_from_results(results)})
    if updated.evidence is not evidence:
        raise AdvisoryPipelineError("advisory pipeline mutated canonical evidence")
    if updated.evidence.findings is not evidence.findings:
        raise AdvisoryPipelineError("advisory pipeline mutated deterministic findings")
    return updated


def evaluate_cohort(
    windows: Sequence[EndpointWindow],
    labels: CohortLabels,
    manifest: CohortManifest,
    *,
    baseline: AnomalyScorer,
    challenger: AnomalyScorer | None = None,
) -> EvaluationReport:
    baseline_scores = baseline.score_windows(windows)
    challenger_scores = challenger.score_windows(windows) if challenger is not None else None
    return compare_detectors(
        windows=windows,
        labels=labels,
        baseline=baseline_scores,
        challenger=challenger_scores,
        baseline_digest=baseline.model_digest,
        challenger_digest=None if challenger is None else challenger.model_digest,
        cohort_id=manifest.cohort_id,
    )


def load_cohort_payload(
    path: Path,
) -> tuple[list[EndpointWindow], CohortLabels, CohortManifest]:
    if not path.is_dir():
        raise AdvisoryPipelineError(f"cohort directory not found: {path}")
    try:
        manifest = CohortManifest.model_validate_json(
            (path / "manifest.json").read_text(encoding="utf-8")
        )
        labels = CohortLabels.model_validate_json(
            (path / "labels.json").read_text(encoding="utf-8")
        )
        raw = json.loads((path / "windows.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AdvisoryPipelineError(f"invalid cohort directory: {path}") from exc
    if not isinstance(raw, list):
        raise AdvisoryPipelineError("windows.json must be a list")
    windows = [EndpointWindow.model_validate(item) for item in raw]
    if manifest.feature_schema_version != FEATURE_SCHEMA_VERSION:
        raise AdvisoryPipelineError(
            "cohort feature schema does not match securemail.advisory_features/v1"
        )
    return windows, labels, manifest


def evaluate_cohort_dir(
    path: Path,
    *,
    baseline: AnomalyScorer,
    challenger: AnomalyScorer | None = None,
) -> EvaluationReport:
    windows, labels, manifest = load_cohort_payload(path)
    try:
        return evaluate_cohort(windows, labels, manifest, baseline=baseline, challenger=challenger)
    except MlDependencyError as exc:
        raise AdvisoryPipelineError(str(exc)) from exc
