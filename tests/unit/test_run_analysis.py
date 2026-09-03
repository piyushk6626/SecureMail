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
    def __init__(self, order: list[str]) -> None:
        self.order = order
        self.seen: Path | None = None

    def run(self, capture_path: Path) -> ZeekRunResult:
        self.order.append("zeek")
        self.seen = capture_path
        return ZeekRunResult(
            image_digest="sha256:" + "a" * 64,
            analyzer_bundle_digest="b" * 64,
            logs={
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
            },
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
