"""Generate Step 1 Scapy TCP reconstruction fixtures (one case per invocation)."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from scapy.packet import Packet

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tcp_common import (  # noqa: E402
    CHUNK,
    CLIENT_ISN,
    CLIENT_PAYLOAD,
    OVERLAP_A,
    OVERLAP_B,
    ROOT,
    SERVER_ISN,
    SERVER_PAYLOAD,
    data_exchange,
    handshake,
    sha256_file,
    tcp_segment,
    teardown,
    write_packets,
    write_provenance,
)

GENERATOR = "tests/fixtures/generators/tcp_degradation_captures.py"


def build_missing_syn() -> tuple[list[Packet], dict[int, int] | None]:
    """Omit SYN/SYN-ACK; start at ACK+payload then FIN."""

    client_seq = CLIENT_ISN + 1
    server_seq = SERVER_ISN + 1
    packets = [
        tcp_segment(
            client_to_server=True,
            seq=client_seq,
            ack=server_seq,
            flags="PA",
            payload=CLIENT_PAYLOAD,
            index=0,
        ),
        tcp_segment(
            client_to_server=False,
            seq=server_seq,
            ack=client_seq + CHUNK,
            flags="PA",
            payload=SERVER_PAYLOAD,
            index=1,
        ),
        tcp_segment(
            client_to_server=True,
            seq=client_seq + CHUNK,
            ack=server_seq + CHUNK,
            flags="A",
            index=2,
        ),
    ]
    packets.extend(teardown(3, client_seq + CHUNK, server_seq + CHUNK))
    return packets, None


def build_missing_fin() -> tuple[list[Packet], dict[int, int] | None]:
    packets, index, client_seq, server_seq = handshake()
    more, _, _, _ = data_exchange(index, client_seq, server_seq, CLIENT_PAYLOAD, SERVER_PAYLOAD)
    packets.extend(more)
    return packets, None


def build_midstream_start() -> tuple[list[Packet], dict[int, int] | None]:
    """Handshake present; first client payload segment omitted (prefix gap)."""

    packets, index, client_seq, server_seq = handshake()
    skipped = CHUNK
    packets.extend(
        [
            tcp_segment(
                client_to_server=True,
                seq=client_seq + skipped,
                ack=server_seq,
                flags="PA",
                payload=CLIENT_PAYLOAD,
                index=index,
            ),
            tcp_segment(
                client_to_server=False,
                seq=server_seq,
                ack=client_seq + skipped + CHUNK,
                flags="PA",
                payload=SERVER_PAYLOAD,
                index=index + 1,
            ),
            tcp_segment(
                client_to_server=True,
                seq=client_seq + skipped + CHUNK,
                ack=server_seq + CHUNK,
                flags="A",
                index=index + 2,
            ),
        ]
    )
    packets.extend(teardown(index + 3, client_seq + skipped + CHUNK, server_seq + CHUNK))
    return packets, None


def build_snaplen_truncation() -> tuple[list[Packet], dict[int, int] | None]:
    packets, index, client_seq, server_seq = handshake()
    more, index, client_seq, server_seq = data_exchange(
        index, client_seq, server_seq, CLIENT_PAYLOAD * 2, SERVER_PAYLOAD
    )
    packets.extend(more)
    packets.extend(teardown(index, client_seq, server_seq))
    # Truncate the first application-data packet (index 3: client payload).
    data_pkt = packets[3]
    wirelen = len(bytes(data_pkt))
    # Keep Ethernet+IPv4+TCP headers plus 16 payload bytes.
    caplen = min(wirelen - 48, 14 + 20 + 20 + 16)
    return packets, {3: caplen}


def build_overlapping_retransmission_conflict() -> tuple[list[Packet], dict[int, int] | None]:
    packets, index, client_seq, server_seq = handshake()
    overlap_offset = 50
    packets.extend(
        [
            tcp_segment(
                client_to_server=True,
                seq=client_seq,
                ack=server_seq,
                flags="PA",
                payload=OVERLAP_A,
                index=index,
            ),
            tcp_segment(
                client_to_server=True,
                seq=client_seq + overlap_offset,
                ack=server_seq,
                flags="PA",
                payload=OVERLAP_B,
                index=index + 1,
            ),
            tcp_segment(
                client_to_server=False,
                seq=server_seq,
                ack=client_seq + overlap_offset + len(OVERLAP_B),
                flags="A",
                index=index + 2,
            ),
        ]
    )
    packets.extend(teardown(index + 3, client_seq + overlap_offset + len(OVERLAP_B), server_seq))
    return packets, None


def build_out_of_order_segments() -> tuple[list[Packet], dict[int, int] | None]:
    packets, index, client_seq, server_seq = handshake()
    first = CLIENT_PAYLOAD
    second = b"D" * CHUNK
    packets.extend(
        [
            tcp_segment(
                client_to_server=True,
                seq=client_seq + len(first),
                ack=server_seq,
                flags="PA",
                payload=second,
                index=index,
            ),
            tcp_segment(
                client_to_server=True,
                seq=client_seq,
                ack=server_seq,
                flags="PA",
                payload=first,
                index=index + 1,
            ),
            tcp_segment(
                client_to_server=False,
                seq=server_seq,
                ack=client_seq + len(first) + len(second),
                flags="PA",
                payload=SERVER_PAYLOAD,
                index=index + 2,
            ),
            tcp_segment(
                client_to_server=True,
                seq=client_seq + len(first) + len(second),
                ack=server_seq + CHUNK,
                flags="A",
                index=index + 3,
            ),
        ]
    )
    packets.extend(teardown(index + 4, client_seq + len(first) + len(second), server_seq + CHUNK))
    return packets, None


def build_duplicate_segments() -> tuple[list[Packet], dict[int, int] | None]:
    packets, index, client_seq, server_seq = handshake()
    packets.extend(
        [
            tcp_segment(
                client_to_server=True,
                seq=client_seq,
                ack=server_seq,
                flags="PA",
                payload=CLIENT_PAYLOAD,
                index=index,
            ),
            tcp_segment(
                client_to_server=True,
                seq=client_seq,
                ack=server_seq,
                flags="PA",
                payload=CLIENT_PAYLOAD,
                index=index + 1,
            ),
            tcp_segment(
                client_to_server=False,
                seq=server_seq,
                ack=client_seq + CHUNK,
                flags="PA",
                payload=SERVER_PAYLOAD,
                index=index + 2,
            ),
            tcp_segment(
                client_to_server=True,
                seq=client_seq + CHUNK,
                ack=server_seq + CHUNK,
                flags="A",
                index=index + 3,
            ),
        ]
    )
    packets.extend(teardown(index + 4, client_seq + CHUNK, server_seq + CHUNK))
    return packets, None


CASES: dict[str, tuple[Callable[[], tuple[list[Packet], dict[int, int] | None]], str]] = {
    "tcp_missing_syn": (
        build_missing_syn,
        "Scapy SMTP-port TCP flow with SYN/SYN-ACK omitted.",
    ),
    "tcp_missing_fin": (
        build_missing_fin,
        "Scapy SMTP-port TCP flow with handshake and payload but no FIN/RST.",
    ),
    "tcp_midstream_start": (
        build_midstream_start,
        "Scapy SMTP-port TCP flow with handshake and omitted first payload.",
    ),
    "tcp_snaplen_truncation": (
        build_snaplen_truncation,
        "Scapy SMTP-port TCP flow with captured_len < original_len on data.",
    ),
    "tcp_overlapping_retransmission_conflict": (
        build_overlapping_retransmission_conflict,
        "Scapy SMTP-port TCP flow with conflicting overlapping retransmission.",
    ),
    "tcp_out_of_order_segments": (
        build_out_of_order_segments,
        "Scapy SMTP-port TCP flow with reordered but complete consistent bytes.",
    ),
    "tcp_duplicate_segments": (
        build_duplicate_segments,
        "Scapy SMTP-port TCP flow with an identical retransmission before ACK.",
    ),
}


def generate_case(case_id: str) -> Path:
    builder, notes = CASES[case_id]
    packets, truncation = builder()
    out_dir = ROOT / "tests" / "fixtures" / case_id
    capture = out_dir / "capture.pcapng"
    write_packets(capture, packets, truncation)
    digest = sha256_file(capture)
    write_provenance(
        out_dir / "provenance.json",
        generator=f"{GENERATOR} --case {case_id} --out tests/fixtures/{case_id}/capture.pcapng",
        capture_sha256=digest,
        notes=notes,
    )
    return capture


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=["all", *sorted(CASES)], default="all")
    args = parser.parse_args()
    selected = list(CASES) if args.case == "all" else [args.case]
    for case_id in selected:
        capture = generate_case(case_id)
        print(f"wrote {capture} sha256={sha256_file(capture)}")


if __name__ == "__main__":
    main()
