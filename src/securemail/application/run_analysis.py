"""Orchestrate one `securemail analyze` run: hash, preflight, Zeek, sessions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from securemail.application.normalize_flows import normalize_flows
from securemail.application.normalize_sessions import (
    needs_imap_pop_corroboration,
    normalize_sessions,
)
from securemail.domain.evidence.run import (
    NORMALIZATION_SCHEMA_VERSION,
    AnalysisRun,
    EvidenceDocument,
)
from securemail.ports.analyzers import (
    AnalyzerError,
    CapturePreflightRunner,
    TSharkRunner,
    ZeekRunner,
)

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}

_CONFIGURATION = {
    "normalization_schema_version": NORMALIZATION_SCHEMA_VERSION,
    "zeek_entry": "zeek/site/__load__.zeek",
    "zeek_deterministic": True,
    "capinfos_entry": "capinfos",
    "flow_normalization": "v1",
    "session_normalization": "v1",
    "tshark_corroboration": "imap_pop",
}


class AnalysisError(Exception):
    """Raised when analysis cannot produce a canonical document."""


class InvalidCaptureError(AnalysisError):
    """Raised when the intake file is not a PCAP or PCAPNG."""


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    capture_path: Path = Field(...)


def configuration_digest() -> str:
    payload = json.dumps(_CONFIGURATION, sort_keys=True, separators=(",", ":")).encode("utf-8")
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
) -> EvidenceDocument:
    capture_path = request.capture_path
    if not capture_path.is_file():
        raise FileNotFoundError(f"capture not found: {capture_path}")
    with capture_path.open("rb") as handle:
        header = handle.read(4)
    if header != PCAPNG_MAGIC and header not in PCAP_MAGICS:
        raise InvalidCaptureError(f"not a PCAP/PCAPNG file: {capture_path}")

    capture_digest = sha256_file(capture_path)
    try:
        preflight = preflight_runner.run(capture_path)
        zeek_result = zeek_runner.run(capture_path)
    except AnalyzerError as exc:
        raise AnalysisError(str(exc)) from exc
    flows = normalize_flows(zeek_result.logs, preflight)
    sessions = normalize_sessions(zeek_result.logs, flows)
    if tshark_runner is not None and needs_imap_pop_corroboration(sessions):
        try:
            tshark_result = tshark_runner.run(capture_path)
        except AnalyzerError as exc:
            raise AnalysisError(str(exc)) from exc
        sessions = normalize_sessions(zeek_result.logs, flows, tshark_frames=tshark_result.frames)
    return EvidenceDocument(
        schema_version=NORMALIZATION_SCHEMA_VERSION,
        run_identity=AnalysisRun(
            capture_sha256=capture_digest,
            analyzer_bundle_digest=zeek_result.analyzer_bundle_digest,
            normalization_schema_version=NORMALIZATION_SCHEMA_VERSION,
            configuration_digest=configuration_digest(),
            policy_pack_version=None,
            trust_store_digest=None,
        ),
        capture_preflight=preflight,
        flows=flows,
        sessions=sessions,
    )
