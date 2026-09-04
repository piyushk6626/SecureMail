"""Orchestrate one `securemail analyze` run: hash, preflight, Zeek, sessions."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from securemail.application.normalize_certificates import normalize_certificates
from securemail.application.normalize_flows import normalize_flows
from securemail.application.normalize_handshakes import normalize_handshakes
from securemail.application.normalize_sessions import (
    needs_tshark_corroboration,
    normalize_sessions,
)
from securemail.domain.evidence.run import (
    EVIDENCE_DOCUMENT_SCHEMA_VERSION,
    NORMALIZATION_SCHEMA_VERSION,
    AnalysisRun,
    EvidenceDocument,
    PolicyProfile,
)
from securemail.domain.findings.dedup import dedup_findings
from securemail.domain.findings.finding import Finding
from securemail.domain.findings.posture import (
    POSTURE_SCHEMA_VERSION,
    PolicyCheck,
    PostureAssessment,
    ScoredEndpointFinding,
    build_posture,
    scored_from_cluster,
)
from securemail.domain.findings.scoring import (
    SCORING_SCHEMA_VERSION,
    AssetContext,
    AssetCriticality,
    BlastRadius,
    ExposureClass,
    ScoreInput,
    compute_score,
)
from securemail.domain.policies.pki.chain_validation import TrustStoreSnapshot
from securemail.domain.policies.rule_engine import (
    PolicyEngineError,
    PolicyPack,
    evaluate_policy_batch,
    resolve_evaluation_clock,
)
from securemail.domain.policies.tls.key_exchange import (
    TlsParameterIndex,
    empty_tls_parameter_index,
)
from securemail.ports.analyzers import (
    AnalyzerError,
    CapturePreflightRunner,
    TSharkRunner,
    ZeekRunner,
)
from securemail.ports.artifacts import ArtifactStore

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}

DEFAULT_EXPIRY_WARNING_SECONDS = 30 * 24 * 60 * 60

_CONFIGURATION = {
    "normalization_schema_version": NORMALIZATION_SCHEMA_VERSION,
    "zeek_entry": "zeek/site/__load__.zeek",
    "zeek_deterministic": True,
    "capinfos_entry": "capinfos",
    "flow_normalization": "v1",
    "session_normalization": "v2",
    "handshake_normalization": "v1",
    "certificate_normalization": "v1",
    "chain_validation": "v1",
    "expiry_warning_seconds": DEFAULT_EXPIRY_WARNING_SECONDS,
    "tshark_corroboration": "smtp_imap_pop_tls_handshake",
    "starttls_evaluation": "v1",
    "scoring_schema_version": SCORING_SCHEMA_VERSION,
    "posture_schema_version": POSTURE_SCHEMA_VERSION,
    "evidence_document_schema_version": EVIDENCE_DOCUMENT_SCHEMA_VERSION,
}


class AnalysisError(Exception):
    """Raised when analysis cannot produce a canonical document."""


class InvalidCaptureError(AnalysisError):
    """Raised when the intake file is not a PCAP or PCAPNG."""


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    capture_path: Path = Field(...)
    analysis_time: datetime | None = None
    expiry_warning_seconds: int = Field(default=DEFAULT_EXPIRY_WARNING_SECONDS, ge=1)
    expected_hostname: str | None = Field(default=None, max_length=253)
    policy_profile: PolicyProfile = PolicyProfile.IETF_CURRENT

    @field_validator("expected_hostname")
    @classmethod
    def _normalize_expected_hostname(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        return text or None


class ScoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["securemail.score_request/v1"] = "securemail.score_request/v1"
    findings: list[Finding] = Field(default_factory=list, max_length=4096)
    policy_checks: list[PolicyCheck] = Field(default_factory=list, max_length=16384)
    asset_context: list[AssetContext] = Field(default_factory=list, max_length=1024)


def score_findings(request: ScoreRequest) -> PostureAssessment:
    """Dedup, score, and publish coverage. Pure orchestration over domain functions."""

    context_by_endpoint = {item.endpoint: item for item in request.asset_context}
    scored: list[ScoredEndpointFinding] = []
    for cluster in dedup_findings(request.findings):
        context = context_by_endpoint.get(cluster.affected_endpoint)
        exposure = ExposureClass.UNKNOWN if context is None else context.exposure
        criticality = AssetCriticality.UNKNOWN if context is None else context.asset_criticality
        blast_radius = BlastRadius.UNKNOWN if context is None else context.blast_radius
        vector = compute_score(
            ScoreInput(
                severity=cluster.severity,
                basis_state=cluster.basis_state,
                exposure=exposure,
                unique_occurrences=cluster.unique_occurrences,
                asset_criticality=criticality,
                blast_radius=blast_radius,
            )
        )
        scored.append(
            scored_from_cluster(
                cluster,
                score=vector.score,
                components=vector.components,
                exposure=exposure,
                asset_criticality=criticality,
                blast_radius=blast_radius,
            )
        )
    return build_posture(scored, request.policy_checks)


class _MemoryArtifactStore:
    def __init__(self) -> None:
        self._items: dict[str, bytes] = {}

    def put(self, payload: bytes) -> str:
        digest = hashlib.sha256(payload).hexdigest()
        self._items[digest] = payload
        return digest

    def get(self, digest: str) -> bytes:
        return self._items[digest]


def configuration_digest(
    *,
    iana_tls_parameters_sha256: str | None = None,
    expiry_warning_seconds: int = DEFAULT_EXPIRY_WARNING_SECONDS,
    expected_hostname: str | None = None,
) -> str:
    digest = iana_tls_parameters_sha256 or empty_tls_parameter_index().digest
    payload = json.dumps(
        {
            **_CONFIGURATION,
            "expiry_warning_seconds": expiry_warning_seconds,
            "expected_hostname": expected_hostname,
            "iana_tls_parameters_sha256": digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def run_analysis(
    request: AnalyzeRequest,
    *,
    zeek_runner: ZeekRunner,
    preflight_runner: CapturePreflightRunner,
    tshark_runner: TSharkRunner | None = None,
    tls_parameters: TlsParameterIndex | None = None,
    artifact_store: ArtifactStore | None = None,
    trust_snapshot: TrustStoreSnapshot | None = None,
    policy_pack: PolicyPack,
    policy_pack_digest: str,
) -> EvidenceDocument:
    capture_path = request.capture_path
    if not capture_path.is_file():
        raise FileNotFoundError(f"capture not found: {capture_path}")
    with capture_path.open("rb") as handle:
        header = handle.read(4)
    if header != PCAPNG_MAGIC and header not in PCAP_MAGICS:
        raise InvalidCaptureError(f"not a PCAP/PCAPNG file: {capture_path}")

    identifiers = tls_parameters if tls_parameters is not None else empty_tls_parameter_index()
    store = artifact_store if artifact_store is not None else _MemoryArtifactStore()
    if request.analysis_time is None:
        analysis_time = datetime.now(UTC)
    else:
        analysis_time = request.analysis_time
    if analysis_time.tzinfo is None:
        analysis_time = analysis_time.replace(tzinfo=UTC)
    else:
        analysis_time = analysis_time.astimezone(UTC)
    warning_window = timedelta(seconds=request.expiry_warning_seconds)
    capture_digest = sha256_file(capture_path)
    try:
        preflight = preflight_runner.run(capture_path)
        zeek_result = zeek_runner.run(capture_path)
    except AnalyzerError as exc:
        raise AnalysisError(str(exc)) from exc
    flows = normalize_flows(zeek_result.logs, preflight)
    sessions = normalize_sessions(zeek_result.logs, flows)
    tshark_frames: list[dict[str, object]] | None = None
    if tshark_runner is not None and needs_tshark_corroboration(sessions, flows, zeek_result.logs):
        try:
            tshark_result = tshark_runner.run(capture_path)
        except AnalyzerError as exc:
            raise AnalysisError(str(exc)) from exc
        tshark_frames = tshark_result.frames
        sessions = normalize_sessions(zeek_result.logs, flows, tshark_frames=tshark_frames)
    handshakes = normalize_handshakes(
        zeek_result.logs,
        flows,
        identifiers,
        tshark_frames=tshark_frames,
    )
    certificates = normalize_certificates(
        zeek_result.logs,
        zeek_result.extracted_certificates,
        handshakes,
        analysis_time=analysis_time,
        expiry_warning=warning_window,
        artifact_store=store,
        trust_snapshot=trust_snapshot,
        expected_hostname=request.expected_hostname,
    )
    try:
        evaluation_time = resolve_evaluation_clock(
            policy_pack,
            analysis_time=analysis_time,
            capture_start_time=preflight.capture_start_time,
        )
    except PolicyEngineError as exc:
        raise AnalysisError(str(exc)) from exc
    evaluation = evaluate_policy_batch(
        pack=policy_pack,
        pack_digest=policy_pack_digest,
        capture_sha256=capture_digest,
        evaluation_time=evaluation_time,
        flows=flows,
        sessions=sessions,
        handshakes=handshakes,
        certificates=certificates,
    )
    posture = score_findings(
        ScoreRequest(
            findings=evaluation.findings,
            policy_checks=evaluation.checks,
        )
    )
    return EvidenceDocument(
        schema_version=EVIDENCE_DOCUMENT_SCHEMA_VERSION,
        run_identity=AnalysisRun(
            capture_sha256=capture_digest,
            analyzer_bundle_digest=zeek_result.analyzer_bundle_digest,
            normalization_schema_version=NORMALIZATION_SCHEMA_VERSION,
            configuration_digest=configuration_digest(
                iana_tls_parameters_sha256=identifiers.digest,
                expiry_warning_seconds=request.expiry_warning_seconds,
                expected_hostname=request.expected_hostname,
            ),
            analysis_time=analysis_time,
            policy_profile=request.policy_profile,
            policy_pack_version=policy_pack_digest,
            trust_store_digest=None if trust_snapshot is None else trust_snapshot.digest,
        ),
        capture_preflight=preflight,
        flows=flows,
        sessions=sessions,
        handshakes=handshakes,
        certificates=certificates,
        findings=evaluation.findings,
        policy_checks=evaluation.checks,
        posture=posture,
    )
