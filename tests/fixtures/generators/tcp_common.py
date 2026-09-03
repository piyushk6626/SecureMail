"""Shared constants and TCP packet builders for Step 1 Scapy fixtures."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import PcapNgWriter

CLIENT_MAC = "02:00:00:00:00:0a"
SERVER_MAC = "02:00:00:00:00:19"
CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.25"
CLIENT_PORT = 49152
SERVER_PORT = 25
CLIENT_ISN = 1000
SERVER_ISN = 2000
BASE_TS = 1_704_067_200.0  # 2024-01-01T00:00:00Z
CHUNK = 64
CLIENT_PAYLOAD = b"C" * CHUNK
SERVER_PAYLOAD = b"S" * CHUNK
OVERLAP_A = b"A" * 200
OVERLAP_B = b"B" * 200
CREATED_AT = "2026-09-03T00:00:00Z"
ROOT = Path(__file__).resolve().parents[3]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def pkt_time(index: int) -> float:
    return BASE_TS + index * 0.01


def tcp_segment(
    *,
    client_to_server: bool,
    seq: int,
    ack: int,
    flags: str,
    payload: bytes = b"",
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


def handshake(start_index: int = 0) -> tuple[list[Packet], int, int, int]:
    """Return packets, next index, next client seq, next server seq."""

    packets = [
        tcp_segment(
            client_to_server=True,
            seq=CLIENT_ISN,
            ack=0,
            flags="S",
            index=start_index,
        ),
        tcp_segment(
            client_to_server=False,
            seq=SERVER_ISN,
            ack=CLIENT_ISN + 1,
            flags="SA",
            index=start_index + 1,
        ),
        tcp_segment(
            client_to_server=True,
            seq=CLIENT_ISN + 1,
            ack=SERVER_ISN + 1,
            flags="A",
            index=start_index + 2,
        ),
    ]
    return packets, start_index + 3, CLIENT_ISN + 1, SERVER_ISN + 1


def data_exchange(
    start_index: int,
    client_seq: int,
    server_seq: int,
    client_payload: bytes,
    server_payload: bytes,
) -> tuple[list[Packet], int, int, int]:
    packets = [
        tcp_segment(
            client_to_server=True,
            seq=client_seq,
            ack=server_seq,
            flags="PA",
            payload=client_payload,
            index=start_index,
        ),
        tcp_segment(
            client_to_server=False,
            seq=server_seq,
            ack=client_seq + len(client_payload),
            flags="PA",
            payload=server_payload,
            index=start_index + 1,
        ),
        tcp_segment(
            client_to_server=True,
            seq=client_seq + len(client_payload),
            ack=server_seq + len(server_payload),
            flags="A",
            index=start_index + 2,
        ),
    ]
    return (
        packets,
        start_index + 3,
        client_seq + len(client_payload),
        server_seq + len(server_payload),
    )


def teardown(
    start_index: int,
    client_seq: int,
    server_seq: int,
) -> list[Packet]:
    return [
        tcp_segment(
            client_to_server=True,
            seq=client_seq,
            ack=server_seq,
            flags="FA",
            index=start_index,
        ),
        tcp_segment(
            client_to_server=False,
            seq=server_seq,
            ack=client_seq + 1,
            flags="A",
            index=start_index + 1,
        ),
        tcp_segment(
            client_to_server=False,
            seq=server_seq,
            ack=client_seq + 1,
            flags="FA",
            index=start_index + 2,
        ),
        tcp_segment(
            client_to_server=True,
            seq=client_seq + 1,
            ack=server_seq + 1,
            flags="A",
            index=start_index + 3,
        ),
    ]


def write_packets(
    path: Path,
    packets: list[Packet],
    truncation: dict[int, int] | None = None,
) -> None:
    """Write PCAPNG. `truncation` maps packet index to captured length < wire length."""

    path.parent.mkdir(parents=True, exist_ok=True)
    limits = truncation or {}
    with PcapNgWriter(str(path)) as writer:
        for index, packet in enumerate(packets):
            caplen = limits.get(index)
            if caplen is None:
                writer.write(packet)
                continue
            if not writer.header_present:
                writer.write_header(packet)
            raw = bytes(packet)
            writer.write_packet(
                raw[:caplen],
                sec=float(packet.time),
                caplen=caplen,
                wirelen=len(raw),
            )


def write_provenance(
    path: Path,
    *,
    generator: str,
    capture_sha256: str,
    notes: str,
    extra_versions: dict[str, str] | None = None,
    source: str = "scapy",
) -> None:
    import scapy

    versions: dict[str, str] = {"scapy": scapy.__version__}
    if extra_versions:
        versions.update(extra_versions)
    payload: dict[str, Any] = {
        "created_at": CREATED_AT,
        "generator": generator,
        "notes": notes,
        "sha256": capture_sha256,
        "source": source,
        "tool_versions": versions,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
