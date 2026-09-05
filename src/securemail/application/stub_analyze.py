"""Docker-free analyze implementation for UI tests. Not an acceptance proof."""

from __future__ import annotations

from datetime import UTC, datetime

from securemail.application.run_analysis import (
    DEFAULT_EXPIRY_WARNING_SECONDS,
    PCAP_MAGICS,
    PCAPNG_MAGIC,
    AnalyzeRequest,
    InvalidCaptureError,
    configuration_digest,
    sha256_file,
)
from securemail.domain.evidence.run import (
    EVIDENCE_DOCUMENT_SCHEMA_VERSION,
    NORMALIZATION_SCHEMA_VERSION,
    AnalysisRun,
    CapturePreflight,
    EvidenceDocument,
)
from securemail.domain.findings.posture import build_posture

_STUB_PACK = "0" * 64
_STUB_BUNDLE = "1" * 64


def stub_analyze(request: AnalyzeRequest) -> EvidenceDocument:
    capture_path = request.capture_path
    if not capture_path.is_file():
        raise FileNotFoundError(f"capture not found: {capture_path}")
    with capture_path.open("rb") as handle:
        header = handle.read(4)
    if header != PCAPNG_MAGIC and header not in PCAP_MAGICS:
        raise InvalidCaptureError(f"not a PCAP/PCAPNG file: {capture_path}")
    analysis_time = request.analysis_time or datetime.now(UTC)
    if analysis_time.tzinfo is None:
        analysis_time = analysis_time.replace(tzinfo=UTC)
    else:
        analysis_time = analysis_time.astimezone(UTC)
    return EvidenceDocument(
        schema_version=EVIDENCE_DOCUMENT_SCHEMA_VERSION,
        run_identity=AnalysisRun(
            capture_sha256=sha256_file(capture_path),
            analyzer_bundle_digest=_STUB_BUNDLE,
            normalization_schema_version=NORMALIZATION_SCHEMA_VERSION,
            configuration_digest=configuration_digest(
                expiry_warning_seconds=request.expiry_warning_seconds
                or DEFAULT_EXPIRY_WARNING_SECONDS,
                expected_hostname=request.expected_hostname,
            ),
            analysis_time=analysis_time,
            policy_profile=request.policy_profile,
            policy_pack_version=_STUB_PACK,
            trust_store_digest=None,
        ),
        capture_preflight=CapturePreflight(
            packet_count=0,
            file_time_precision="nanosecond",
            truncated_packets_present=False,
        ),
        flows=[],
        sessions=[],
        handshakes=[],
        certificates=[],
        findings=[],
        policy_checks=[],
        posture=build_posture([], []),
    )
