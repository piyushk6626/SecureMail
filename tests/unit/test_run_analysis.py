"""Use-case hashes the capture before invoking preflight and Zeek."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from securemail.adapters.reference_data.policy_packs import load_policy_pack
from securemail.application.run_analysis import (
    AnalysisError,
    AnalyzeRequest,
    configuration_digest,
    run_analysis,
)
from securemail.domain.evidence.run import CapturePreflight, PolicyProfile
from securemail.domain.policies.rule_engine import PolicyPack
from securemail.ports.analyzers import ZeekRunResult

_PINNED_ANALYSIS_TIME = datetime(2026, 9, 4, 12, tzinfo=UTC)


def _ietf_pack() -> tuple[PolicyPack, str]:
    return load_policy_pack(PolicyProfile.IETF_CURRENT)


class _FakePreflight:
    def __init__(self, order: list[str], *, capture_start_time: datetime | None = None) -> None:
        self.order = order
        self._capture_start_time = capture_start_time

    def run(self, capture_path: Path) -> CapturePreflight:
        self.order.append("preflight")
        assert capture_path.is_file()
        return CapturePreflight(
            packet_count=1,
            file_time_precision="microsecond",
            truncated_packets_present=False,
            original_packet_bytes=36,
            capture_duration_seconds=0.0,
            capture_start_time=self._capture_start_time,
        )


class _FakeZeek:
    def __init__(
        self,
        order: list[str],
        logs: dict[str, list[dict[str, object]]] | None = None,
    ) -> None:
        self.order = order
        self.seen: Path | None = None
        self._logs = logs or {
            "conn.log": [
                {
                    "uid": "Ctest",
                    "id.orig_h": "192.0.2.10",
                    "id.orig_p": 49152,
                    "id.resp_h": "192.0.2.25",
                    "id.resp_p": 25,
                    "proto": "tcp",
                    "history": "ShADadFf",
                    "conn_state": "SF",
                    "missed_bytes": 0,
                    "orig_bytes": 64,
                    "resp_bytes": 64,
                }
            ]
        }

    def run(self, capture_path: Path) -> ZeekRunResult:
        self.order.append("zeek")
        self.seen = capture_path
        return ZeekRunResult(
            image_digest="sha256:" + "a" * 64,
            analyzer_bundle_digest="b" * 64,
            logs=self._logs,
        )


def test_run_analysis_hashes_before_returning_document(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcapng"
    payload = b"\x0a\x0d\x0d\x0a" + b"\x00" * 32
    capture.write_bytes(payload)
    order: list[str] = []
    fake_zeek = _FakeZeek(order)
    pack, digest = _ietf_pack()
    document = run_analysis(
        AnalyzeRequest(capture_path=capture, analysis_time=_PINNED_ANALYSIS_TIME),
        zeek_runner=fake_zeek,
        preflight_runner=_FakePreflight(order),
        policy_pack=pack,
        policy_pack_digest=digest,
    )
    assert order == ["preflight", "zeek"]
    assert fake_zeek.seen == capture
    assert document.schema_version == "v2"
    assert document.run_identity.normalization_schema_version == "v1"
    assert document.run_identity.analyzer_bundle_digest == "b" * 64
    assert document.run_identity.capture_sha256 == __import__("hashlib").sha256(payload).hexdigest()
    assert document.run_identity.configuration_digest == configuration_digest()
    assert document.run_identity.policy_pack_version == digest
    assert document.run_identity.policy_profile is PolicyProfile.IETF_CURRENT
    assert document.run_identity.analysis_time == _PINNED_ANALYSIS_TIME
    assert document.run_identity.trust_store_digest is None
    assert document.capture_preflight.packet_count == 1
    assert document.findings == []
    assert document.policy_checks == []
    assert document.posture.assessment_state.value == "none"
    assert document.posture.risk_score is None
    assert len(document.flows) == 1
    assert document.flows[0].uid == "Ctest"
    assert document.sessions == []
    assert document.handshakes == []
    assert document.certificates == []


def test_run_analysis_normalizes_email_sessions(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)
    logs: dict[str, list[dict[str, object]]] = {
        "conn.log": [
            {
                "uid": "Ctest",
                "id.orig_h": "192.0.2.10",
                "id.orig_p": 49152,
                "id.resp_h": "192.0.2.25",
                "id.resp_p": 2525,
                "proto": "tcp",
                "history": "ShADadFf",
                "conn_state": "SF",
                "missed_bytes": 0,
                "orig_bytes": 64,
                "resp_bytes": 64,
            }
        ],
        "sm_email.log": [
            {
                "uid": "Ctest",
                "protocol": "smtp",
                "is_orig": True,
                "event_type": "request",
                "command": "EHLO",
            }
        ],
    }
    pack, digest = _ietf_pack()
    document = run_analysis(
        AnalyzeRequest(capture_path=capture, analysis_time=_PINNED_ANALYSIS_TIME),
        zeek_runner=_FakeZeek([], logs),
        preflight_runner=_FakePreflight([]),
        policy_pack=pack,
        policy_pack_digest=digest,
    )
    assert len(document.sessions) == 1
    assert document.sessions[0].uid == "Ctest"
    assert document.sessions[0].protocol is not None
    assert document.sessions[0].protocol.value == "smtp"
    assert document.sessions[0].port_hint.value == "none"
    assert document.sessions[0].payload_evidence.value == "smtp"


def test_run_analysis_assesses_starttls_from_ssl_history(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)
    logs: dict[str, list[dict[str, object]]] = {
        "conn.log": [
            {
                "uid": "Ctest",
                "id.orig_h": "192.0.2.10",
                "id.orig_p": 49152,
                "id.resp_h": "192.0.2.25",
                "id.resp_p": 25,
                "proto": "tcp",
                "history": "ShADadFf",
                "conn_state": "SF",
                "missed_bytes": 0,
                "orig_bytes": 64,
                "resp_bytes": 64,
            }
        ],
        "sm_email.log": [
            {
                "uid": "Ctest",
                "protocol": "smtp",
                "event_type": "reply",
                "command": "EHLO",
                "reply_code": 250,
                "text": "STARTTLS",
            },
            {
                "uid": "Ctest",
                "protocol": "smtp",
                "is_orig": True,
                "event_type": "request",
                "command": "STARTTLS",
            },
            {
                "uid": "Ctest",
                "protocol": "smtp",
                "event_type": "reply",
                "reply_code": 220,
                "text": "Ready",
            },
        ],
        "ssl.log": [{"uid": "Ctest", "ssl_history": "Csx", "established": True}],
    }
    pack, digest = _ietf_pack()
    document = run_analysis(
        AnalyzeRequest(capture_path=capture, analysis_time=_PINNED_ANALYSIS_TIME),
        zeek_runner=_FakeZeek([], logs),
        preflight_runner=_FakePreflight([]),
        policy_pack=pack,
        policy_pack_digest=digest,
    )
    assert document.sessions[0].explicit_upgrade is not None
    assert document.sessions[0].explicit_upgrade.state is not None
    assert document.sessions[0].explicit_upgrade.state.value == "tls_established"
    assert len(document.handshakes) == 1
    assert document.handshakes[0].uid == "Ctest"
    assert document.handshakes[0].ssl_history == "Csx"


def test_run_analysis_records_trust_store_digest_when_snapshot_provided(
    tmp_path: Path,
) -> None:
    from securemail.adapters.pki.trust_store import load_trust_store_snapshot

    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)
    snapshot = load_trust_store_snapshot()
    hostname = "mail.example.test"
    pack, digest = _ietf_pack()
    document = run_analysis(
        AnalyzeRequest(
            capture_path=capture,
            expected_hostname=hostname,
            analysis_time=_PINNED_ANALYSIS_TIME,
        ),
        zeek_runner=_FakeZeek([]),
        preflight_runner=_FakePreflight([]),
        trust_snapshot=snapshot,
        policy_pack=pack,
        policy_pack_digest=digest,
    )
    assert document.run_identity.trust_store_digest == snapshot.digest
    assert document.run_identity.configuration_digest == configuration_digest(
        expected_hostname=hostname
    )


def test_historical_profile_requires_capture_start_time(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)
    pack, digest = load_policy_pack(PolicyProfile.HISTORICAL_AT_CAPTURE)
    with pytest.raises(AnalysisError, match="capture start time unavailable"):
        run_analysis(
            AnalyzeRequest(
                capture_path=capture,
                analysis_time=_PINNED_ANALYSIS_TIME,
                policy_profile=PolicyProfile.HISTORICAL_AT_CAPTURE,
            ),
            zeek_runner=_FakeZeek([]),
            preflight_runner=_FakePreflight([]),
            policy_pack=pack,
            policy_pack_digest=digest,
        )
