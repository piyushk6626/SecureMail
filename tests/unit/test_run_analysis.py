"""Use-case hashes the capture before invoking preflight and Zeek."""

from pathlib import Path

from securemail.application.run_analysis import AnalyzeRequest, configuration_digest, run_analysis
from securemail.domain.evidence.run import CapturePreflight
from securemail.ports.analyzers import ZeekRunResult


class _FakePreflight:
    def __init__(self, order: list[str]) -> None:
        self.order = order

    def run(self, capture_path: Path) -> CapturePreflight:
        self.order.append("preflight")
        assert capture_path.is_file()
        return CapturePreflight(
            packet_count=1,
            file_time_precision="microsecond",
            truncated_packets_present=False,
            original_packet_bytes=36,
            capture_duration_seconds=0.0,
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
    document = run_analysis(
        AnalyzeRequest(capture_path=capture),
        zeek_runner=fake_zeek,
        preflight_runner=_FakePreflight(order),
    )
    assert order == ["preflight", "zeek"]
    assert fake_zeek.seen == capture
    assert document.schema_version == "v0"
    assert document.run_identity.normalization_schema_version == "v0"
    assert document.run_identity.analyzer_bundle_digest == "b" * 64
    assert document.run_identity.capture_sha256 == __import__("hashlib").sha256(payload).hexdigest()
    assert document.run_identity.configuration_digest == configuration_digest()
    assert document.run_identity.policy_pack_version is None
    assert document.run_identity.trust_store_digest is None
    assert document.capture_preflight.packet_count == 1
    assert len(document.flows) == 1
    assert document.flows[0].uid == "Ctest"
    assert document.sessions == []


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
    document = run_analysis(
        AnalyzeRequest(capture_path=capture),
        zeek_runner=_FakeZeek([], logs),
        preflight_runner=_FakePreflight([]),
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
    document = run_analysis(
        AnalyzeRequest(capture_path=capture),
        zeek_runner=_FakeZeek([], logs),
        preflight_runner=_FakePreflight([]),
    )
    assert document.sessions[0].explicit_upgrade is not None
    assert document.sessions[0].explicit_upgrade.state is not None
    assert document.sessions[0].explicit_upgrade.state.value == "tls_established"
