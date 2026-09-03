"""Generate Step 3 Scapy STARTTLS/STLS adversarial fixtures."""

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

GENERATOR = "tests/fixtures/generators/scapy_starttls_captures.py"
CLIENT_PORT = 49152


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
        ether = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        ip = IP(src=CLIENT_IP, dst=SERVER_IP, ttl=64, id=index + 1)
        sport, dport = CLIENT_PORT, server_port
    else:
        ether = Ether(src=SERVER_MAC, dst=CLIENT_MAC)
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


def build_smtp_rejected() -> list[Packet]:
    return _dialogue(
        25,
        [
            ("server", b"220 mail.example.test ESMTP\r\n"),
            ("client", b"EHLO client.example.test\r\n"),
            ("server", b"250-mail.example.test Hello\r\n250-STARTTLS\r\n250 OK\r\n"),
            ("client", b"STARTTLS\r\n"),
            ("server", b"454 TLS not available\r\n"),
            ("client", b"QUIT\r\n"),
            ("server", b"221 Bye\r\n"),
        ],
    )


def build_imap_rejected() -> list[Packet]:
    return _dialogue(
        143,
        [
            ("server", b"* OK IMAP4rev1 ready\r\n"),
            ("client", b"a001 CAPABILITY\r\n"),
            ("server", b"* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK CAPABILITY completed\r\n"),
            ("client", b"a002 STARTTLS\r\n"),
            ("server", b"a002 NO TLS unavailable\r\n"),
            ("client", b"a003 LOGOUT\r\n"),
            ("server", b"* BYE logging out\r\na003 OK LOGOUT completed\r\n"),
        ],
    )


def build_pop3_rejected() -> list[Packet]:
    return _dialogue(
        110,
        [
            ("server", b"+OK POP3 ready\r\n"),
            ("client", b"CAPA\r\n"),
            ("server", b"+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n"),
            ("client", b"STLS\r\n"),
            ("server", b"-ERR TLS unavailable\r\n"),
            ("client", b"QUIT\r\n"),
            ("server", b"+OK Bye\r\n"),
        ],
    )


def build_imap_stripped() -> list[Packet]:
    return _dialogue(
        143,
        [
            ("server", b"* OK IMAP4rev1 ready\r\n"),
            ("client", b"a001 CAPABILITY\r\n"),
            ("server", b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\na001 OK CAPABILITY completed\r\n"),
            ("client", b"a002 STARTTLS\r\n"),
            ("server", b"a002 OK begin TLS\r\n"),
            ("client", b"a003 LOGOUT\r\n"),
            ("server", b"* BYE logging out\r\na003 OK LOGOUT completed\r\n"),
        ],
    )


def build_smtp_stripped() -> list[Packet]:
    return _dialogue(
        25,
        [
            ("server", b"220 mail.example.test ESMTP\r\n"),
            ("client", b"EHLO client.example.test\r\n"),
            ("server", b"250-mail.example.test Hello\r\n250 AUTH PLAIN\r\n"),
            ("client", b"STARTTLS\r\n"),
            ("server", b"220 Ready to start TLS\r\n"),
            ("client", b"QUIT\r\n"),
            ("server", b"221 Bye\r\n"),
        ],
    )


def build_pop3_stripped() -> list[Packet]:
    return _dialogue(
        110,
        [
            ("server", b"+OK POP3 ready\r\n"),
            ("client", b"CAPA\r\n"),
            ("server", b"+OK Capability list follows\r\nUSER\r\n.\r\n"),
            ("client", b"STLS\r\n"),
            ("server", b"+OK Begin TLS\r\n"),
            ("client", b"QUIT\r\n"),
            ("server", b"+OK Bye\r\n"),
        ],
    )


def build_smtp_violation() -> list[Packet]:
    return _dialogue(
        25,
        [
            ("server", b"220 mail.example.test ESMTP\r\n"),
            ("client", b"EHLO client.example.test\r\n"),
            ("server", b"250-mail.example.test Hello\r\n250-STARTTLS\r\n250 OK\r\n"),
            ("client", b"STARTTLS\r\n"),
            ("server", b"220 Ready to start TLS\r\n"),
            ("client", b"AUTH PLAIN AHVzZXIAc2VjcmV0\r\n"),
            ("server", b"235 2.7.0 OK\r\n"),
        ],
    )


def build_imap_violation() -> list[Packet]:
    return _dialogue(
        143,
        [
            ("server", b"* OK IMAP4rev1 ready\r\n"),
            ("client", b"a001 CAPABILITY\r\n"),
            ("server", b"* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK CAPABILITY completed\r\n"),
            ("client", b"a002 STARTTLS\r\n"),
            ("server", b"a002 OK begin TLS\r\n"),
            ("client", b"a003 LOGIN user secret\r\n"),
            ("server", b"a003 OK LOGIN completed\r\n"),
        ],
    )


def build_pop3_violation() -> list[Packet]:
    return _dialogue(
        110,
        [
            ("server", b"+OK POP3 ready\r\n"),
            ("client", b"CAPA\r\n"),
            ("server", b"+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n"),
            ("client", b"STLS\r\n"),
            ("server", b"+OK Begin TLS\r\n"),
            ("client", b"USER account\r\n"),
            ("server", b"+OK\r\n"),
            ("client", b"PASS secret\r\n"),
            ("server", b"+OK Logged in\r\n"),
        ],
    )


def build_smtp_auth_after_failed() -> list[Packet]:
    return _dialogue(
        25,
        [
            ("server", b"220 mail.example.test ESMTP\r\n"),
            ("client", b"EHLO client.example.test\r\n"),
            ("server", b"250-mail.example.test Hello\r\n250-STARTTLS\r\n250 OK\r\n"),
            ("client", b"STARTTLS\r\n"),
            ("server", b"454 TLS not available\r\n"),
            ("client", b"AUTH PLAIN AHVzZXIAc2VjcmV0\r\n"),
            ("server", b"235 2.7.0 OK\r\n"),
        ],
    )


def build_imap_login_after_failed() -> list[Packet]:
    return _dialogue(
        143,
        [
            ("server", b"* OK IMAP4rev1 ready\r\n"),
            ("client", b"a001 CAPABILITY\r\n"),
            ("server", b"* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK CAPABILITY completed\r\n"),
            ("client", b"a002 STARTTLS\r\n"),
            ("server", b"a002 NO TLS unavailable\r\n"),
            ("client", b"a003 LOGIN user secret\r\n"),
            ("server", b"a003 OK LOGIN completed\r\n"),
        ],
    )


def build_pop3_auth_after_failed() -> list[Packet]:
    return _dialogue(
        110,
        [
            ("server", b"+OK POP3 ready\r\n"),
            ("client", b"CAPA\r\n"),
            ("server", b"+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n"),
            ("client", b"STLS\r\n"),
            ("server", b"-ERR TLS unavailable\r\n"),
            ("client", b"USER account\r\n"),
            ("server", b"+OK\r\n"),
            ("client", b"PASS secret\r\n"),
            ("server", b"+OK Logged in\r\n"),
        ],
    )


CASES: dict[str, tuple[Callable[[], list[Packet]], str]] = {
    "smtp_starttls_rejected": (
        build_smtp_rejected,
        "Scapy SMTP STARTTLS rejected with 454 after being advertised.",
    ),
    "imap_starttls_rejected": (
        build_imap_rejected,
        "Scapy IMAP tagged STARTTLS rejected with NO after STARTTLS was advertised.",
    ),
    "pop3_stls_rejected": (
        build_pop3_rejected,
        "Scapy POP3 STLS rejected with -ERR after STLS was advertised in CAPA.",
    ),
    "imap_starttls_capability_stripped": (
        build_imap_stripped,
        "Scapy IMAP CAPABILITY omits STARTTLS but the server still accepts STARTTLS.",
    ),
    "smtp_starttls_capability_stripped": (
        build_smtp_stripped,
        "Scapy SMTP EHLO omits STARTTLS but the server still accepts STARTTLS.",
    ),
    "pop3_stls_capability_stripped": (
        build_pop3_stripped,
        "Scapy POP3 CAPA omits STLS but the server still accepts STLS.",
    ),
    "smtp_starttls_mid_transition_violation": (
        build_smtp_violation,
        "Scapy SMTP AUTH issued in plaintext after STARTTLS was accepted.",
    ),
    "imap_starttls_mid_transition_violation": (
        build_imap_violation,
        "Scapy IMAP LOGIN issued in plaintext after STARTTLS was accepted.",
    ),
    "pop3_stls_mid_transition_violation": (
        build_pop3_violation,
        "Scapy POP3 USER/PASS issued in plaintext after STLS was accepted.",
    ),
    "smtp_plaintext_auth_after_failed_upgrade": (
        build_smtp_auth_after_failed,
        "Scapy SMTP AUTH after a rejected STARTTLS upgrade.",
    ),
    "imap_plaintext_login_after_failed_upgrade": (
        build_imap_login_after_failed,
        "Scapy IMAP LOGIN after a rejected STARTTLS upgrade.",
    ),
    "pop3_plaintext_auth_after_failed_upgrade": (
        build_pop3_auth_after_failed,
        "Scapy POP3 USER/PASS after a rejected STLS upgrade.",
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
