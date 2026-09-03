"""Generate Step 2 Scapy protocol-identification fixtures."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
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

GENERATOR = "tests/fixtures/generators/scapy_protocol_captures.py"
CLIENT_PORT = 49152
CLIENT_MAC_SRC = CLIENT_MAC
SERVER_MAC_SRC = SERVER_MAC


def _segment(
    *,
    client_to_server: bool,
    seq: int,
    ack: int,
    flags: str,
    payload: bytes,
    index: int,
    server_port: int,
) -> Packet:
    if client_to_server:
        ether = Ether(src=CLIENT_MAC_SRC, dst=SERVER_MAC_SRC)
        ip = IP(src=CLIENT_IP, dst=SERVER_IP, ttl=64, id=index + 1)
        sport, dport = CLIENT_PORT, server_port
    else:
        ether = Ether(src=SERVER_MAC_SRC, dst=CLIENT_MAC_SRC)
        ip = IP(src=SERVER_IP, dst=CLIENT_IP, ttl=64, id=index + 1)
        sport, dport = server_port, CLIENT_PORT
    tcp = TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=8192)
    packet: Packet = ether / ip / tcp
    if payload:
        packet = packet / Raw(load=payload)
    del packet[IP].chksum
    del packet[TCP].chksum
    packet.time = pkt_time(index)
    return packet


def _handshake(server_port: int) -> tuple[list[Packet], int, int, int]:
    packets = [
        _segment(
            client_to_server=True,
            seq=CLIENT_ISN,
            ack=0,
            flags="S",
            payload=b"",
            index=0,
            server_port=server_port,
        ),
        _segment(
            client_to_server=False,
            seq=SERVER_ISN,
            ack=CLIENT_ISN + 1,
            flags="SA",
            payload=b"",
            index=1,
            server_port=server_port,
        ),
        _segment(
            client_to_server=True,
            seq=CLIENT_ISN + 1,
            ack=SERVER_ISN + 1,
            flags="A",
            payload=b"",
            index=2,
            server_port=server_port,
        ),
    ]
    return packets, 3, CLIENT_ISN + 1, SERVER_ISN + 1


def _teardown(start_index: int, client_seq: int, server_seq: int, server_port: int) -> list[Packet]:
    return [
        _segment(
            client_to_server=True,
            seq=client_seq,
            ack=server_seq,
            flags="FA",
            payload=b"",
            index=start_index,
            server_port=server_port,
        ),
        _segment(
            client_to_server=False,
            seq=server_seq,
            ack=client_seq + 1,
            flags="A",
            payload=b"",
            index=start_index + 1,
            server_port=server_port,
        ),
        _segment(
            client_to_server=False,
            seq=server_seq,
            ack=client_seq + 1,
            flags="FA",
            payload=b"",
            index=start_index + 2,
            server_port=server_port,
        ),
        _segment(
            client_to_server=True,
            seq=client_seq + 1,
            ack=server_seq + 1,
            flags="A",
            payload=b"",
            index=start_index + 3,
            server_port=server_port,
        ),
    ]


def _dialogue(server_port: int, turns: Sequence[tuple[str, bytes]]) -> list[Packet]:
    packets, index, client_seq, server_seq = _handshake(server_port)
    for speaker, payload in turns:
        client_to_server = speaker == "client"
        packets.append(
            _segment(
                client_to_server=client_to_server,
                seq=client_seq if client_to_server else server_seq,
                ack=server_seq if client_to_server else client_seq,
                flags="PA",
                payload=payload,
                index=index,
                server_port=server_port,
            )
        )
        if client_to_server:
            client_seq += len(payload)
        else:
            server_seq += len(payload)
        index += 1
        packets.append(
            _segment(
                client_to_server=not client_to_server,
                seq=server_seq if client_to_server else client_seq,
                ack=client_seq if client_to_server else server_seq,
                flags="A",
                payload=b"",
                index=index,
                server_port=server_port,
            )
        )
        index += 1
    packets.extend(_teardown(index, client_seq, server_seq, server_port))
    return packets


def build_smtp_nonstandard() -> list[Packet]:
    return _dialogue(
        2525,
        [
            ("server", b"220 mail.example.test ESMTP\r\n"),
            ("client", b"EHLO client.example.test\r\n"),
            ("server", b"250-mail.example.test Hello\r\n250-STARTTLS\r\n250 OK\r\n"),
            ("client", b"QUIT\r\n"),
            ("server", b"221 Bye\r\n"),
        ],
    )


def build_imap_nonstandard() -> list[Packet]:
    return _dialogue(
        1143,
        [
            ("server", b"* OK IMAP4rev1 ready\r\n"),
            ("client", b"a001 CAPABILITY\r\n"),
            ("server", b"* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK CAPABILITY completed\r\n"),
            ("client", b"a002 LOGOUT\r\n"),
            ("server", b"* BYE logging out\r\na002 OK LOGOUT completed\r\n"),
        ],
    )


def build_pop3_nonstandard() -> list[Packet]:
    return _dialogue(
        1110,
        [
            ("server", b"+OK POP3 ready\r\n"),
            ("client", b"CAPA\r\n"),
            ("server", b"+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n"),
            ("client", b"QUIT\r\n"),
            ("server", b"+OK Bye\r\n"),
        ],
    )


def build_ambiguous_banner() -> list[Packet]:
    return _dialogue(
        25,
        [
            ("server", b"GREETINGS FROM THE WIRE\r\n"),
            ("client", b"PING\r\n"),
            ("server", b"PONG\r\n"),
        ],
    )


CASES: dict[str, tuple[Callable[[], list[Packet]], str]] = {
    "smtp_nonstandard_port": (
        build_smtp_nonstandard,
        "Scapy SMTP EHLO/QUIT on TCP/2525. Payload identification, not port.",
    ),
    "imap_nonstandard_port": (
        build_imap_nonstandard,
        "Scapy IMAP CAPABILITY/LOGOUT on TCP/1143. Payload identification, not port.",
    ),
    "pop3_nonstandard_port": (
        build_pop3_nonstandard,
        "Scapy POP3 CAPA/QUIT on TCP/1110. Payload identification, not port.",
    ),
    "email_ambiguous_banner": (
        build_ambiguous_banner,
        "Scapy CRLF greeting on TCP/25 that is not SMTP, IMAP, or POP3.",
    ),
}


def generate_case(case_id: str) -> Path:
    builder, notes = CASES[case_id]
    packets = builder()
    out_dir = ROOT / "tests" / "fixtures" / case_id
    capture = out_dir / "capture.pcapng"
    write_packets(capture, packets)
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
