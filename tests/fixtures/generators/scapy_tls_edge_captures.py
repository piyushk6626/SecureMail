"""Scapy TLS edge cases: supported_versions vs legacy record version, truncated ClientHello."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tcp_common import (  # noqa: E402
    CLIENT_IP,
    CLIENT_ISN,
    CLIENT_MAC,
    ROOT,
    SERVER_IP,
    SERVER_ISN,
    SERVER_MAC,
    pkt_time,
    sha256_file,
    write_packets,
    write_provenance,
)

GENERATOR = "tests/fixtures/generators/scapy_tls_edge_captures.py"
CLIENT_PORT = 49152
SERVER_PORT = 4433
TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F


def _segment(
    *,
    client_to_server: bool,
    seq: int,
    ack: int,
    flags: str,
    payload: bytes,
    index: int,
) -> Packet:
    if client_to_server:
        ether = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        ip = IP(src=CLIENT_IP, dst=SERVER_IP, ttl=64, id=index + 1)
        sport, dport = CLIENT_PORT, SERVER_PORT
    else:
        ether = Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        ip = IP(src=SERVER_IP, dst=CLIENT_IP, ttl=64, id=index + 1)
        sport, dport = SERVER_PORT, CLIENT_PORT
    tcp = TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=8192)
    packet: Packet = ether / ip / tcp
    if payload:
        packet = packet / Raw(load=payload)
    del packet[IP].chksum
    del packet[TCP].chksum
    packet.time = pkt_time(index)
    return packet


def _handshake() -> tuple[list[Packet], int, int, int]:
    packets = [
        _segment(
            client_to_server=True,
            seq=CLIENT_ISN,
            ack=0,
            flags="S",
            payload=b"",
            index=0,
        ),
        _segment(
            client_to_server=False,
            seq=SERVER_ISN,
            ack=CLIENT_ISN + 1,
            flags="SA",
            payload=b"",
            index=1,
        ),
        _segment(
            client_to_server=True,
            seq=CLIENT_ISN + 1,
            ack=SERVER_ISN + 1,
            flags="A",
            payload=b"",
            index=2,
        ),
    ]
    return packets, 3, CLIENT_ISN + 1, SERVER_ISN + 1


def _tls_record(payload: bytes, *, record_version: int = 0x0301) -> bytes:
    return b"\x16" + struct.pack("!HH", record_version, len(payload)) + payload


def _handshake_message(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + struct.pack("!I", len(body))[1:] + body


def _ext_supported_versions_client(versions: list[int]) -> bytes:
    inner = b"".join(struct.pack("!H", version) for version in versions)
    data = bytes([len(inner)]) + inner
    return struct.pack("!HH", 0x002B, len(data)) + data


def _ext_supported_versions_server(version: int) -> bytes:
    data = struct.pack("!H", version)
    return struct.pack("!HH", 0x002B, len(data)) + data


def _client_hello(*, legacy_version: int, offered: list[int]) -> bytes:
    random = b"\x11" * 32
    ciphers = struct.pack("!H", TLS_RSA_WITH_AES_128_CBC_SHA)
    extensions = _ext_supported_versions_client(offered)
    body = (
        struct.pack("!H", legacy_version)
        + random
        + b"\x00"
        + struct.pack("!H", len(ciphers))
        + ciphers
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    return _tls_record(_handshake_message(1, body), record_version=legacy_version)


def _server_hello(*, legacy_version: int, selected: int) -> bytes:
    random = b"\x22" * 32
    extensions = _ext_supported_versions_server(selected)
    body = (
        struct.pack("!H", legacy_version)
        + random
        + b"\x00"
        + struct.pack("!H", TLS_RSA_WITH_AES_128_CBC_SHA)
        + b"\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    return _tls_record(_handshake_message(2, body), record_version=legacy_version)


def _server_hello_done(*, record_version: int) -> bytes:
    return _tls_record(_handshake_message(14, b""), record_version=record_version)


def _write_case(case_id: str, packets: list[Packet], notes: str) -> Path:
    out_dir = ROOT / "tests" / "fixtures" / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    capture = out_dir / "capture.pcapng"
    write_packets(capture, packets)
    write_provenance(
        out_dir / "provenance.json",
        generator=f"{GENERATOR} --case {case_id}",
        capture_sha256=sha256_file(capture),
        notes=notes,
    )
    return capture


def generate_supported_versions_precedence() -> Path:
    packets, index, client_seq, server_seq = _handshake()
    client_hello = _client_hello(legacy_version=0x0301, offered=[0x0303])
    server_hello = _server_hello(legacy_version=0x0301, selected=0x0303)
    server_done = _server_hello_done(record_version=0x0301)
    packets.append(
        _segment(
            client_to_server=True,
            seq=client_seq,
            ack=server_seq,
            flags="PA",
            payload=client_hello,
            index=index,
        )
    )
    client_seq += len(client_hello)
    index += 1
    packets.append(
        _segment(
            client_to_server=False,
            seq=server_seq,
            ack=client_seq,
            flags="PA",
            payload=server_hello + server_done,
            index=index,
        )
    )
    server_seq += len(server_hello) + len(server_done)
    index += 1
    packets.append(
        _segment(
            client_to_server=True,
            seq=client_seq,
            ack=server_seq,
            flags="FA",
            payload=b"",
            index=index,
        )
    )
    return _write_case(
        "tls_supported_versions_precedence",
        packets,
        (
            "Scapy TLS handshake with legacy record/hello version TLS 1.0 (0x0301) while "
            "supported_versions selects TLS 1.2 (0x0303)."
        ),
    )


def generate_truncated_client_hello() -> Path:
    packets, index, client_seq, server_seq = _handshake()
    client_hello = _client_hello(legacy_version=0x0303, offered=[0x0304, 0x0303])
    packets.append(
        _segment(
            client_to_server=True,
            seq=client_seq,
            ack=server_seq,
            flags="PA",
            payload=client_hello,
            index=index,
        )
    )
    client_seq += len(client_hello)
    index += 1
    packets.append(
        _segment(
            client_to_server=True,
            seq=client_seq,
            ack=server_seq,
            flags="FA",
            payload=b"",
            index=index,
        )
    )
    return _write_case(
        "tls_truncated_client_hello",
        packets,
        "Scapy TLS handshake that stops after a complete ClientHello; no ServerHello.",
    )


CASES = {
    "tls_supported_versions_precedence": generate_supported_versions_precedence,
    "tls_truncated_client_hello": generate_truncated_client_hello,
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=["all", *sorted(CASES)], default="all")
    args = parser.parse_args()
    selected = list(CASES) if args.case == "all" else [args.case]
    for case_id in selected:
        capture = CASES[case_id]()
        print(f"wrote {capture} sha256={sha256_file(capture)}")


if __name__ == "__main__":
    main()
