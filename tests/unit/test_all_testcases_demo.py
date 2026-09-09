"""Tests for the standalone all-testcases dashboard PCAPNG pipeline."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapNgReader

SCRIPT = Path("tools/build_all_testcases_demo.py")


def test_demo_pipeline_uses_contracts_without_reading_lfs_packet_bytes(tmp_path: Path) -> None:
    output = tmp_path / "demo.pcapng"
    manifest = tmp_path / "demo.manifest.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--public-corpus-mode",
            "synthetic",
            "--include",
            "cert_valid_current",
            "--include",
            "smtp_starttls_success",
            "--out",
            str(output),
            "--manifest",
            str(manifest),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["case_count"] == 2
    assert {case["case_id"] for case in payload["cases"]} == {
        "cert_valid_current",
        "smtp_starttls_success",
    }
    assert payload["lfs_fixture_bytes_read"] is False
    balance = payload["packet_balance"]
    assert balance["successful_packet_count"] >= 2 * balance["error_prone_packet_count"]
    assert balance["achieved_successful_to_error_ratio"] >= 2
    assert sum(balance[f"{category}_packet_count"] for category in (
        "successful", "error_prone", "neutral"
    )) == payload["packet_count"]
    reader = RawPcapNgReader(str(output))
    rows = list(reader)
    reader.close()
    assert rows
    assert {metadata.linktype for _packet, metadata in rows} == {1}
    for data, _metadata in rows:
        packet = Ether(data)
        network = packet.getlayer(IP) or packet.getlayer(IPv6)
        if network is not None:
            assert network.src != network.dst


def test_default_configuration_is_complete_json() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--print-default-config"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["public_corpus_mode"] == "online"
    assert payload["include"] == ["*"]
    assert payload["preserve_public_timestamps"] is True
    assert payload["client_ipv6_network"] == "fd20::/64"
    assert payload["balance_successful_packets"] is True
    assert payload["successful_to_error_packet_ratio"] == 2.0
