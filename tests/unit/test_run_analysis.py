"""Use-case skeleton hashes the capture before invoking Zeek."""

from pathlib import Path

from securemail.application.run_analysis import AnalyzeRequest, configuration_digest, run_analysis
from securemail.ports.analyzers import ZeekRunResult


class _FakeZeek:
    def __init__(self) -> None:
        self.seen: Path | None = None

    def run(self, capture_path: Path) -> ZeekRunResult:
        self.seen = capture_path
        return ZeekRunResult(
            image_digest="sha256:" + "a" * 64,
            analyzer_bundle_digest="b" * 64,
            logs={"conn.log": []},
        )


def test_run_analysis_hashes_before_returning_document(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcapng"
    payload = b"\x0a\x0d\x0d\x0a" + b"\x00" * 32
    capture.write_bytes(payload)
    fake = _FakeZeek()
    document = run_analysis(AnalyzeRequest(capture_path=capture), zeek_runner=fake)
    assert fake.seen == capture
    assert document.schema_version == "v0"
    assert document.run_identity.normalization_schema_version == "v0"
    assert document.run_identity.analyzer_bundle_digest == "b" * 64
    assert document.run_identity.capture_sha256 == __import__("hashlib").sha256(payload).hexdigest()
    assert document.run_identity.configuration_digest == configuration_digest()
    assert document.run_identity.policy_pack_version is None
    assert document.run_identity.trust_store_digest is None
