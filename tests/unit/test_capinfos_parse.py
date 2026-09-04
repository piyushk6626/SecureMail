"""capinfos long-form parser and argv contract."""

from pathlib import Path

import pytest

from securemail.adapters.analyzers.capinfos_runner import (
    CAPINFOS_ARGV,
    DockerCapinfosRunner,
    parse_capinfos_text,
)
from securemail.adapters.analyzers.sandbox import MAX_OUTPUT_BYTES
from securemail.ports.analyzers import AnalyzerError


def test_parse_capinfos_empty_fixture_sample() -> None:
    text = """
File name:           /data/capture.pcapng
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: (not set)
Number of packets:   5
Data size:           264 bytes
Capture duration:    0.000000 seconds
"""
    preflight = parse_capinfos_text(text)
    assert preflight.packet_count == 5
    assert preflight.file_time_precision == "microsecond"
    assert preflight.packet_size_limit is None
    assert preflight.packet_size_limit_min_inferred is None
    assert preflight.truncated_packets_present is False
    assert preflight.original_packet_bytes == 264
    assert preflight.capture_duration_seconds == 0.0
    assert preflight.capture_start_time is None


def test_parse_capinfos_first_packet_time_as_utc() -> None:
    text = """
File name:           /data/capture.pcapng
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: (not set)
Number of packets:   5
Data size:           264 bytes
Capture duration:    0.000000 seconds
First packet time:   2026-09-03 22:28:36.123456
"""
    preflight = parse_capinfos_text(text)
    assert preflight.capture_start_time is not None
    assert preflight.capture_start_time.tzinfo is not None
    assert preflight.capture_start_time.year == 2026
    assert preflight.capture_start_time.month == 9
    assert preflight.capture_start_time.day == 3
    assert preflight.capture_start_time.hour == 22
    assert preflight.capture_start_time.minute == 28
    assert preflight.capture_start_time.second == 36


def test_parse_capinfos_inferred_truncation_range() -> None:
    text = """
File name:           /data/capture.pcapng
File timestamp precision:  nanoseconds (9)
Packet size limit:   inferred: 74 bytes - 154 bytes (range)
Number of packets:   12
Data size:           1800 bytes
Capture duration:    1.250000 seconds
"""
    preflight = parse_capinfos_text(text)
    assert preflight.truncated_packets_present is True
    assert preflight.packet_size_limit_min_inferred == 74
    assert preflight.packet_size_limit_max_inferred == 154
    assert preflight.file_time_precision == "nanosecond"


def test_parse_capinfos_rejects_missing_packet_count() -> None:
    with pytest.raises(AnalyzerError, match="packet count"):
        parse_capinfos_text("File name: x\n")


def test_parse_capinfos_rejects_oversized_output() -> None:
    huge = "Number of packets: 1\n" + ("x" * (MAX_OUTPUT_BYTES + 1))
    with pytest.raises(AnalyzerError, match="size bound"):
        parse_capinfos_text(huge)


def test_capinfos_argv_is_fixed_and_offline(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"\x0a\x0d\x0d\x0a")
    argv = DockerCapinfosRunner(repo_root=tmp_path, lock_path=tmp_path / "lock.json").argv(capture)
    assert argv[0] == "docker"
    assert "--network=none" in argv
    assert "--entrypoint" in argv
    assert "capinfos" in argv
    assert "-a" in argv
    assert argv[-len(CAPINFOS_ARGV) + 1 :] == list(CAPINFOS_ARGV[1:])
    assert not any("&&" in part or "|" in part for part in argv)
