"""Analyzer argv is a fixed list and includes the sandbox contract."""

from pathlib import Path

from securemail.adapters.analyzers.sandbox import sandbox_docker_flags
from securemail.adapters.analyzers.tshark_runner import TSHARK_FIELDS, DockerTSharkRunner
from securemail.adapters.analyzers.zeek_runner import DockerZeekRunner


def test_sandbox_flags_include_network_none() -> None:
    flags = sandbox_docker_flags()
    assert "--network=none" in flags
    assert "--read-only" in flags
    assert "--cap-drop=ALL" in flags
    assert "no-new-privileges" in flags
    assert "65532:65532" in flags


def test_zeek_argv_is_fixed_and_offline(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"\x0a\x0d\x0d\x0a")
    output = tmp_path / "out"
    output.mkdir()
    argv = DockerZeekRunner(repo_root=tmp_path, lock_path=tmp_path / "lock.json").argv(
        capture, output
    )
    assert argv[0] == "docker"
    assert argv[1] == "run"
    assert "--network=none" in argv
    assert "LogAscii::use_json=T" in argv
    assert "/opt/securemail/zeek/site/__load__.zeek" in argv
    assert not any("&&" in part or "|" in part for part in argv)


def test_tshark_argv_uses_allowlisted_fields_only(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"\x0a\x0d\x0d\x0a")
    output = tmp_path / "out"
    output.mkdir()
    argv = DockerTSharkRunner(repo_root=tmp_path, lock_path=tmp_path / "lock.json").argv(
        capture, output
    )
    assert "--network=none" in argv
    assert "-T" in argv
    asserted_fields = [argv[index + 1] for index, part in enumerate(argv) if part == "-e"]
    assert asserted_fields == list(TSHARK_FIELDS)
    assert "frame" in argv
