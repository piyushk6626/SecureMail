"""Scapy TLS 1.2 handshake with a malformed/truncated certificate message."""

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

GENERATOR = "tests/fixtures/generators/scapy_cert_malformed_captures.py"
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


def _tls_record(payload: bytes, *, record_version: int = 0x0303) -> bytes:
    return b"\x16" + struct.pack("!HH", record_version, len(payload)) + payload


def _handshake_message(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + struct.pack("!I", len(body))[1:] + body


def _u24(value: int) -> bytes:
    return struct.pack("!I", value)[1:]


def _client_hello() -> bytes:
    random = b"\x11" * 32
    ciphers = struct.pack("!H", TLS_RSA_WITH_AES_128_CBC_SHA)
    body = (
        struct.pack("!H", 0x0303)
        + random
        + b"\x00"
        + struct.pack("!H", len(ciphers))
        + ciphers
        + b"\x01\x00"
        + struct.pack("!H", 0)
    )
    return _tls_record(_handshake_message(1, body))


def _server_hello() -> bytes:
    random = b"\x22" * 32
    body = (
        struct.pack("!H", 0x0303)
        + random
        + b"\x00"
        + struct.pack("!H", TLS_RSA_WITH_AES_128_CBC_SHA)
        + b"\x00"
        + struct.pack("!H", 0)
    )
    return _tls_record(_handshake_message(2, body))


def _malformed_certificate_der() -> bytes:
    inner = b"\x05\x00"
    for _ in range(24):
        inner = b"\x30" + bytes([len(inner)]) + inner
    claimed = b"\x30\x82\x10\x00" + inner
    return claimed


def _certificate_message(der: bytes) -> bytes:
    cert_entry = _u24(len(der)) + der
    body = _u24(len(cert_entry)) + cert_entry
    return _tls_record(_handshake_message(11, body))


def _server_hello_done() -> bytes:
    return _tls_record(_handshake_message(14, b""))


def generate_malformed_asn1() -> Path:
    packets, index, client_seq, server_seq = _handshake()
    client_hello = _client_hello()
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
    der = _malformed_certificate_der()
    server_payload = _server_hello() + _certificate_message(der) + _server_hello_done()
    packets.append(
        _segment(
            client_to_server=False,
            seq=server_seq,
            ack=client_seq,
            flags="PA",
            payload=server_payload,
            index=index,
        )
    )
    server_seq += len(server_payload)
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
    out_dir = ROOT / "tests" / "fixtures" / "cert_malformed_asn1"
    out_dir.mkdir(parents=True, exist_ok=True)
    capture = out_dir / "capture.pcapng"
    write_packets(capture, packets)
    write_provenance(
        out_dir / "provenance.json",
        generator=f"{GENERATOR} --case cert_malformed_asn1",
        capture_sha256=sha256_file(capture),
        notes=(
            "Scapy TLS 1.2 Certificate message with truncated/over-nested ASN.1. "
            "The parser must fail safely rather than crash or hang."
        ),
    )
    return capture


CASES = {"cert_malformed_asn1": generate_malformed_asn1}


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
