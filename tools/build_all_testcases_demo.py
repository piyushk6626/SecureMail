"""Build one dashboard-demo PCAPNG covering all capture-backed test cases.

The pipeline never reads or modifies Git LFS packet pointers. It inventories
the reviewed ``expected.json`` contracts, synthesizes isolated lab/adversarial
traffic, and uses pinned online packet sources for public-corpus cases. It has
no imports from the SecureMail application package.
"""

from __future__ import annotations

import argparse
import fnmatch
import gzip
import hashlib
import importlib.util
import ipaddress
import json
import math
import os
import shlex
import shutil
import struct
import sys
import tempfile
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import PcapNgReader, RawPcapNgReader, RawPcapReader

SCHEMA_VERSION = "securemail.all-testcases-demo/v1"
DEFAULT_START = "2026-09-04T08:00:00Z"
SMTP_URL = ("https://wiki.wireshark.org/uploads/__moin_import__/attachments/"
            "SampleCaptures/smtp.pcap")
IMAP_URL = ("https://wiki.wireshark.org/uploads/__moin_import__/attachments/"
            "SampleCaptures/imap.cap")
ULTIMATE_URL = "https://weberblog.net/wp-content/uploads/2020/02/The-Ultimate-PCAP.pcapng.gz"
PUBLIC_HASHES = {
    "smtp": "17ad230db1b6fd5dd18eb311092df1cf6eb162054bdb47697b89bef5a86a47ab",
    "imap": "fa9a9bcca7b7f2943d740d46b075565b0dbbcc0f60ab321bf577a7be9724b5a8",
    "ultimate": "96359b8119ec53f347af4b7e55727d020d2ff60f30b0906da350b8564f49f49c",
}
ULTIMATE_FLOWS = {
    "smtp_starttls_public_corpus": frozenset({
        ("2001:470:1f0b:16b0:f83f:53c1:be1:eca1", 54043),
        ("2a01:488:42:1000:50ed:8588:8a:c570", 587),
    }),
    "imap_starttls_public_corpus": frozenset({
        ("2001:470:1f0b:16b0:f83f:53c1:be1:eca1", 54137),
        ("2a01:488:42:1000:50ed:8588:8a:c570", 143),
    }),
    "pop3_stls_public_corpus": frozenset({
        ("2001:470:1f0b:16b0:f83f:53c1:be1:eca1", 54004),
        ("2a01:488:42:1000:50ed:8588:8a:c570", 110),
    }),
    "tls12_public_corpus": frozenset({
        ("2001:470:1f0b:16b0:221:70ff:feb2:e6c", 33712),
        ("2a02:2e0:3fe:1001:7777:772e:2:85", 443),
    }),
    "cert_chain_public_corpus": frozenset({
        ("2001:470:1f0b:16b0:221:70ff:feb2:e6c", 33712),
        ("2a02:2e0:3fe:1001:7777:772e:2:85", 443),
    }),
    "tls13_public_corpus": frozenset({
        ("194.247.5.7", 57556), ("85.25.246.38", 8080),
    }),
}
VERSION_CODES = {"SSLv3": 0x0300, "TLSv10": 0x0301, "TLSv11": 0x0302,
                 "TLSv12": 0x0303, "TLSv13": 0x0304}


class DemoError(Exception):
    """Raised when the demo dataset cannot be built safely."""


@dataclass(frozen=True)
class Config:
    contract_root: Path
    output_capture: Path
    output_manifest: Path | None
    cache_root: Path
    source_capture_root: Path | None = None
    include: tuple[str, ...] = ("*",)
    exclude: tuple[str, ...] = ()
    public_corpus_mode: str = "online"
    public_source_urls: dict[str, str] = field(default_factory=lambda: {
        "smtp": SMTP_URL, "imap": IMAP_URL, "ultimate": ULTIMATE_URL,
    })
    public_source_sha256: dict[str, str] = field(default_factory=lambda: dict(PUBLIC_HASHES))
    download_timeout_seconds: int = 120
    timeline_start: str = DEFAULT_START
    case_gap_seconds: float = 30.0
    preserve_public_timestamps: bool = True
    annotate_packets: bool = True
    refresh_generated_sources: bool = False
    balance_successful_packets: bool = True
    successful_to_error_packet_ratio: float = 2.0
    replace_existing: bool = False


@dataclass(frozen=True)
class PacketRow:
    case_id: str
    timestamp_ns: int
    data: bytes
    wirelen: int
    source: str


@dataclass(frozen=True)
class Result:
    output_capture: Path
    output_manifest: Path
    case_ids: tuple[str, ...]
    packet_count: int
    capture_sha256: str


def repo_root() -> Path:
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "pyproject.toml").is_file() and (candidate / "tests").is_dir():
            return candidate
    raise DemoError("could not locate repository root")


def default_config() -> Config:
    root = repo_root()
    output = root / "out" / "all-testcases.pcapng"
    return Config(
        contract_root=root / "tests" / "fixtures",
        output_capture=output,
        output_manifest=output.with_suffix(".manifest.json"),
        cache_root=root / "out" / ".combined-pcap-cache",
    )


def build(config: Config) -> Result:
    _validate_config(config)
    cases = _discover_cases(config)
    online = _load_online(config) if config.public_corpus_mode == "online" else {}
    rows: list[PacketRow] = []
    case_manifest: list[dict[str, Any]] = []
    classifications: dict[str, str] = {}
    for index, (case_id, expected_path) in enumerate(cases):
        expected = _read_object(expected_path)
        classification = _case_classification(expected)
        classifications[case_id] = classification
        provenance = _read_object(expected_path.with_name("provenance.json"))
        case_rows = online.get(case_id)
        content_origin = "online_public_corpus"
        source_capture_sha256 = None
        if not case_rows:
            source_capture = _actual_capture(case_id, expected_path, provenance, config)
            source_capture_sha256 = _sha256(source_capture)
            case_rows = _read_capture(source_capture, case_id, "generated_or_resolved_capture")
            content_origin = "resolved_capture" if config.source_capture_root else \
                f"canonical_{provenance.get('source', 'generator')}"
        case_rows = _rebase_case(case_rows, case_id, index, config)
        rows.extend(case_rows)
        case_manifest.append({
            "case_id": case_id,
            "source": provenance.get("source"),
            "packet_content_origin": content_origin,
            "source_capture_sha256": source_capture_sha256,
            "reviewed_capture_sha256": provenance.get("sha256"),
            "classification": classification,
            "contract": str(expected_path),
            "contract_sha256": _sha256(expected_path),
            "base_packet_count": len(case_rows),
        })
    rows, packet_balance = _balance_packets(rows, classifications, len(cases), config)
    rows.sort(key=lambda row: (row.timestamp_ns, row.case_id))
    manifest_path = config.output_manifest or config.output_capture.with_suffix(".manifest.json")
    _prepare_outputs(config.output_capture, manifest_path, config.replace_existing)
    _write_pcapng(config.output_capture, rows, annotate=config.annotate_packets)
    digest = _sha256(config.output_capture)
    positions: dict[str, list[int]] = {case_id: [] for case_id, _ in cases}
    for number, row in enumerate(rows, 1):
        positions[row.case_id].append(number)
    for item in case_manifest:
        packet_count = len(positions[item["case_id"]])
        item["packet_count"] = packet_count
        item["replica_packet_count"] = packet_count - int(item["base_packet_count"])
        item["output_packet_ranges"] = _ranges(positions[item["case_id"]])
    _write_json(manifest_path, {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "generator": "tools/build_all_testcases_demo.py",
        "output_capture": str(config.output_capture),
        "output_capture_sha256": digest,
        "packet_count": len(rows),
        "case_count": len(cases),
        "configuration": _config_payload(config),
        "lfs_fixture_bytes_read": False,
        "contract_data_used_for_packet_content": False,
        "demo_pipeline": {
            "contract_case_count": len(cases),
            "lfs_fixture_bytes_read": False,
            "public_corpus_mode": config.public_corpus_mode,
            "packet_content": "actual captures only; no contract-derived packet synthesis",
        },
        "packet_balance": packet_balance,
        "cases": case_manifest,
        "limitations": [
            "Use the fixture harness, not this dashboard demo, for conformance testing.",
            "JSON-only scoring/report/ML fixtures have no valid packet representation.",
            "Scapy-authored malformed cases use their canonical repository generators.",
        ],
    })
    return Result(config.output_capture, manifest_path, tuple(case_id for case_id, _ in cases),
                  len(rows), digest)


def _validate_config(config: Config) -> None:
    if not config.contract_root.is_dir():
        raise DemoError(f"contract root does not exist: {config.contract_root}")
    if config.public_corpus_mode not in {"online", "synthetic"}:
        raise DemoError("public_corpus_mode must be online or synthetic")
    if config.case_gap_seconds <= 0 or config.download_timeout_seconds <= 0:
        raise DemoError("timeouts and case gap must be positive")
    if not math.isfinite(config.successful_to_error_packet_ratio) or \
            config.successful_to_error_packet_ratio <= 0:
        raise DemoError("successful_to_error_packet_ratio must be finite and positive")
    if config.source_capture_root is not None and not config.source_capture_root.is_dir():
        raise DemoError(f"source capture root does not exist: {config.source_capture_root}")
    _timestamp_ns(config.timeline_start)


def _discover_cases(config: Config) -> list[tuple[str, Path]]:
    result = []
    for expected in sorted(config.contract_root.glob("*/expected.json")):
        case_id = expected.parent.name
        if not (expected.parent / "capture.pcapng").is_file():
            continue
        if not any(fnmatch.fnmatchcase(case_id, pattern) for pattern in config.include):
            continue
        if any(fnmatch.fnmatchcase(case_id, pattern) for pattern in config.exclude):
            continue
        result.append((case_id, expected))
    if not result:
        raise DemoError("no capture-backed cases matched the configuration")
    return result


def _load_online(config: Config) -> dict[str, list[PacketRow]]:
    config.cache_root.mkdir(parents=True, exist_ok=True)
    smtp = _download(config, "smtp", "smtp.pcap")
    imap = _download(config, "imap", "imap.cap")
    archive = _download(config, "ultimate", "ultimate.pcapng.gz")
    ultimate = config.cache_root / "ultimate.pcapng"
    if not ultimate.is_file():
        ultimate.write_bytes(gzip.decompress(archive.read_bytes()))
    result = {
        "smtp_public_corpus": _read_capture(smtp, "smtp_public_corpus"),
        "imap_public_corpus": _read_capture(imap, "imap_public_corpus"),
    }
    result.update(_extract_ultimate(ultimate))
    missing = sorted({*ULTIMATE_FLOWS} - {*result})
    if missing:
        raise DemoError("online source missing pinned streams: " + ", ".join(missing))
    return result


def _download(config: Config, key: str, filename: str) -> Path:
    destination = config.cache_root / filename
    expected = config.public_source_sha256[key]
    if destination.is_file() and _sha256(destination) == expected:
        return destination
    request = urllib.request.Request(config.public_source_urls[key],
                                     headers={"User-Agent": "SecureMail-dashboard-demo/1"})
    try:
        with urllib.request.urlopen(request, timeout=config.download_timeout_seconds) as response:  # noqa: S310,E501
            payload = response.read()
    except OSError as exc:
        raise DemoError(f"could not download {key}: {exc}") from exc
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected:
        raise DemoError(f"{key} SHA-256 {actual} does not match pinned {expected}")
    destination.write_bytes(payload)
    return destination


def _read_capture(path: Path, case_id: str) -> list[PacketRow]:
    reader_type = PcapNgReader if path.suffix == ".pcapng" else PcapReader
    rows = []
    with reader_type(str(path)) as reader:
        for packet in reader:
            if not isinstance(packet, Ether):
                continue
            data = bytes(packet)
            rows.append(PacketRow(case_id, int(float(packet.time) * 1e9), data,
                                  int(getattr(packet, "wirelen", len(data))),
                                  "online_public_corpus"))
    return rows


def _extract_ultimate(path: Path) -> dict[str, list[PacketRow]]:
    result: dict[str, list[PacketRow]] = {key: [] for key in ULTIMATE_FLOWS}
    with PcapNgReader(str(path)) as reader:
        for packet in reader:
            if not isinstance(packet, Ether) or TCP not in packet:
                continue
            network = packet.getlayer(IP) or packet.getlayer(IPv6)
            if network is None:
                continue
            flow = frozenset({(str(network.src), int(packet[TCP].sport)),
                              (str(network.dst), int(packet[TCP].dport))})
            for case_id, selected in ULTIMATE_FLOWS.items():
                if flow == selected:
                    data = bytes(packet)
                    result[case_id].append(PacketRow(
                        case_id, int(float(packet.time) * 1e9), data,
                        int(getattr(packet, "wirelen", len(data))),
                        "online_public_corpus",
                    ))
    return {key: value for key, value in result.items() if value}


def _synthesize(case_id: str, expected: dict[str, Any], index: int,
                config: Config) -> list[PacketRow]:
    start = _timestamp_ns(config.timeline_start) + int(index * config.case_gap_seconds * 1e9)
    if case_id == "empty":
        base = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        packets = [
            base.copy() / ARP(psrc="10.0.0.10", pdst="10.0.0.1"),
            base.copy() / IP(src="10.0.0.10", dst="10.0.0.1") / ICMP(),
            base.copy() / IP(src="10.0.0.10", dst="10.0.0.53")
            / UDP(sport=53000, dport=53) / Raw(b"bounded background traffic"),
        ]
        return [PacketRow(case_id, start + number * 1_000_000, bytes(packet),
                          len(bytes(packet)), "synthetic_from_contract")
                for number, packet in enumerate(packets)]
    sessions = expected.get("sessions") or []
    handshakes = expected.get("handshakes") or []
    certificates = expected.get("certificates") or []
    session = sessions[0] if sessions else None
    protocol = session.get("protocol") if session else None
    protocol = protocol if protocol in {"smtp", "imap", "pop3"} else None
    port = _server_port(expected, protocol)
    dialogue = _dialogue(protocol, session, case_id)
    rng = random.Random(config.random_seed + index)
    tls = _tls_payloads(case_id, handshakes, certificates, protocol, rng)
    client = _address(config.client_network, index)
    server = _address(config.server_network, index)
    return _tcp_case(case_id, client, server, port, dialogue, tls, start, rng)


def _server_port(expected: dict[str, Any], protocol: str | None) -> int:
    flows = expected.get("flows") or []
    if flows and isinstance(flows[0].get("resp", {}).get("port"), int):
        return int(flows[0]["resp"]["port"])
    return {"smtp": 25, "imap": 143, "pop3": 110}.get(protocol, 4433)


def _dialogue(protocol: str | None, session: dict[str, Any] | None,
              case_id: str) -> list[tuple[bool, bytes]]:
    if protocol is None:
        return [(False, b"Welcome to messaging service\r\n")] if case_id == \
            "email_ambiguous_banner" else []
    rows: list[tuple[bool, bytes]] = []
    for event in session.get("events", []) if session else []:
        if event.get("kind") in {"starttls", "capability", "confirmation"}:
            continue
        orig = event.get("direction") == "orig"
        command = event.get("command")
        text = event.get("text")
        if protocol == "smtp":
            if orig and command and command != ">":
                value = f"{command}{' demo' if event.get('argument') else ''}\r\n"
            elif not orig:
                value = f"{event.get('reply_code') or 250} {text or 'OK'}\r\n"
            else:
                continue
        elif protocol == "imap":
            if orig and command:
                value = f"{event.get('tag') or 'a001'} {command}\r\n"
            elif not orig:
                value = f"{event.get('tag') or '*'} {text or 'OK'}\r\n"
            else:
                continue
        else:
            if orig and command:
                suffix = " demo" if command in {"USER", "PASS"} else ""
                value = f"{command}{suffix}\r\n"
            elif not orig:
                prefix = "-ERR" if text and "ERR" in text else "+OK"
                value = f"{prefix} {text or 'ready'}\r\n"
            else:
                continue
        row = (orig, value.encode("ascii", errors="replace"))
        if not rows or rows[-1] != row:
            rows.append(row)
    if rows:
        return rows
    return {
        "smtp": [(False, b"220 demo.example ESMTP\r\n"),
                 (True, b"EHLO client.example\r\n")],
        "imap": [(False, b"* OK IMAP4rev1 ready\r\n"),
                 (True, b"a001 CAPABILITY\r\n")],
        "pop3": [(False, b"+OK POP3 ready\r\n"), (True, b"CAPA\r\n")],
    }[protocol]


def _tls_payloads(case_id: str, handshakes: list[dict[str, Any]],
                  certificates: list[dict[str, Any]], protocol: str | None,
                  rng: random.Random) -> list[tuple[bool, bytes]]:
    wants_tls = bool(handshakes) or "implicit_tls" in case_id or \
        "starttls_success" in case_id or "stls_success" in case_id
    if not wants_tls:
        return []
    handshake = handshakes[0] if handshakes else {}
    version_name = handshake.get("version", {}).get("selected") or "TLSv12"
    version = VERSION_CODES.get(version_name, 0x0303)
    cipher = int(handshake.get("cipher_suite", {}).get("code") or "0xC02F", 16)
    hostname = "wrong.example.test" if "san_mismatch" in case_id else "securemail.test"
    client_hello = _client_hello(version, cipher, hostname,
                                 protocol if "implicit_tls" in case_id else None, rng)
    if "truncated_client_hello" in case_id:
        return [(True, client_hello)]
    if "hello_retry" in case_id:
        return [(True, client_hello), (False, _server_hello(version, cipher, rng, True)),
                (True, client_hello), (False, _server_hello(version, cipher, rng, False))]
    server = _server_hello(version, cipher, rng, False)
    if version < 0x0304:
        certs = _certificates(case_id, certificates)
        if "malformed_asn1" in case_id:
            certs = [b"\x30\x82\xff\xff\x30\x82"]
        if certs:
            chain = b"".join(_u24(len(cert)) + cert for cert in certs)
            server += _record(version, _handshake(11, _u24(len(chain)) + chain))
        server += _record(version, _handshake(14, b""))
    client_finish = _record(version, _handshake(16, b"\x00")) + \
        b"\x14\x03\x03\x00\x01\x01"
    server_finish = b"\x14\x03\x03\x00\x01\x01\x17\x03\x03\x00\x10" + b"\x00" * 16
    return [(True, client_hello), (False, server),
            (True, client_finish), (False, server_finish)]


def _client_hello(version: int, cipher: int, hostname: str, alpn: str | None,
                  rng: random.Random) -> bytes:
    legacy = min(version, 0x0303)
    host = hostname.encode()
    extensions = (struct.pack("!HHH", 0, len(host) + 5, len(host) + 3)
                  + b"\x00" + struct.pack("!H", len(host)) + host)
    if version >= 0x0304:
        extensions += struct.pack("!HHBH", 43, 3, 2, 0x0304)
        extensions += struct.pack("!HH", 45, 2) + b"\x01\x01"
        key = rng.randbytes(32)
        share = struct.pack("!HH", 29, len(key)) + key
        extensions += struct.pack("!HHH", 51, len(share) + 2, len(share)) + share
    if alpn:
        token = alpn.encode()
        value = struct.pack("!H", len(token) + 1) + bytes([len(token)]) + token
        extensions += struct.pack("!HH", 16, len(value)) + value
    body = (struct.pack("!H", legacy) + rng.randbytes(32) + b"\x00"
            + struct.pack("!HH", 2, cipher) + b"\x01\x00"
            + struct.pack("!H", len(extensions)) + extensions)
    return _record(legacy, _handshake(1, body))


def _server_hello(version: int, cipher: int, rng: random.Random, hrr: bool) -> bytes:
    legacy = min(version, 0x0303)
    hello_random = bytes.fromhex(
        "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
    ) if hrr else rng.randbytes(32)
    extensions = b""
    if version >= 0x0304:
        extensions = struct.pack("!HHH", 43, 2, 0x0304)
        share = struct.pack("!H", 23) if hrr else struct.pack("!HH", 29, 1) + b"\x01"
        extensions += struct.pack("!HH", 51, len(share)) + share
    body = (struct.pack("!H", legacy) + hello_random + b"\x00"
            + struct.pack("!H", cipher) + b"\x00"
            + struct.pack("!H", len(extensions)) + extensions)
    return _record(legacy, _handshake(2, body))


def _certificates(case_id: str, facts: list[dict[str, Any]]) -> list[bytes]:
    fact = facts[0] if facts else {}
    if str(fact.get("public_key_algorithm") or "RSA") == "ECDSA":
        key: Any = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537,
                                       key_size=max(1024, int(fact.get("public_key_size") or 2048)))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "securemail.test")])
    san = "other.example.test" if "san_mismatch" in case_id else "securemail.test"
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(max(1, int(hashlib.sha256(case_id.encode()).hexdigest()[:30], 16)))
            .not_valid_before(_datetime(str(fact.get("not_before") or "2020-01-01T00:00:00Z")))
            .not_valid_after(_datetime(str(fact.get("not_after") or "2099-01-01T00:00:00Z")))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), False)
            .sign(key, hashes.SHA256()))
    encoded = cert.public_bytes(serialization.Encoding.DER)
    if "sha1_signed" in case_id:
        encoded = encoded.replace(bytes.fromhex("06092a864886f70d01010b"),
                                  bytes.fromhex("06092a864886f70d010105"))
    return [encoded]


def _tcp_case(case_id: str, client: str, server: str, port: int,
              dialogue: list[tuple[bool, bytes]], tls: list[tuple[bool, bytes]],
              start: int, rng: random.Random) -> list[PacketRow]:
    sport, cseq, sseq = 40000 + rng.randrange(20000), 10000, 30000
    packets: list[Packet] = []

    def add(orig: bool, flags: str, payload: bytes = b"", seq: int | None = None) -> None:
        nonlocal cseq, sseq
        src, dst = (client, server) if orig else (server, client)
        source_port, destination_port = (sport, port) if orig else (port, sport)
        current = seq if seq is not None else (cseq if orig else sseq)
        ack = sseq if orig else cseq
        packet: Packet = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                          / IP(src=src, dst=dst)
                          / TCP(sport=source_port, dport=destination_port,
                                seq=current, ack=ack, flags=flags, window=8192))
        if payload:
            packet = packet / Raw(payload)
        packets.append(packet)
        if seq is None:
            advance = len(payload) + int("S" in flags or "F" in flags)
            if orig:
                cseq += advance
            else:
                sseq += advance

    degraded = case_id in {"tcp_missing_syn", "tcp_midstream_start"}
    if not degraded:
        add(True, "S")
        add(False, "SA")
        add(True, "A")
    payload_start = len(packets)
    for orig, payload in [*dialogue, *tls]:
        add(orig, "PA", payload)
    if not dialogue and not tls:
        add(False, "PA", b"220 demo.example ESMTP\r\n")
    if case_id == "tcp_duplicate_segments" and len(packets) > payload_start:
        packets.insert(payload_start + 1, packets[payload_start].copy())
    if case_id == "tcp_overlapping_retransmission_conflict" and len(packets) > payload_start:
        conflict = packets[payload_start].copy()
        if Raw in conflict:
            conflict[Raw].load = b"550 conflicting bytes\r\n"
        packets.insert(payload_start + 1, conflict)
    if case_id == "tcp_out_of_order_segments" and len(packets) > payload_start + 1:
        packets[payload_start], packets[payload_start + 1] = \
            packets[payload_start + 1], packets[payload_start]
    if case_id not in {"tcp_missing_fin", "tcp_midstream_start", "tcp_snaplen_truncation"}:
        add(True, "FA")
        add(False, "FA")
    rows = []
    for number, packet in enumerate(packets):
        data, wirelen = bytes(packet), len(bytes(packet))
        if case_id == "tcp_snaplen_truncation" and number == payload_start:
            data = data[:max(40, len(data) - 12)]
        rows.append(PacketRow(case_id, start + number * 1_000_000, data, wirelen,
                              "synthetic_from_contract"))
    return rows


def _isolate_case(rows: list[PacketRow], case_id: str, index: int,
                  config: Config) -> list[PacketRow]:
    first = min(row.timestamp_ns for row in rows)
    target = _timestamp_ns(config.timeline_start) + int(index * config.case_gap_seconds * 1e9)
    address_maps: dict[int, dict[str, str]] = {4: {}, 6: {}}
    result = []
    for row in rows:
        packet = Ether(row.data)
        network = packet.getlayer(IP) or packet.getlayer(IPv6)
        if network is not None:
            if isinstance(network, IPv6):
                client = _address(config.client_ipv6_network, index)
                server = _address(config.server_ipv6_network, index)
            else:
                client = _address(config.client_network, index)
                server = _address(config.server_network, index)
            address_map = address_maps[network.version]
            original_src, original_dst = str(network.src), str(network.dst)
            if original_src not in address_map and original_dst not in address_map:
                address_map[original_src], address_map[original_dst] = client, server
            elif original_src not in address_map:
                address_map[original_src] = (
                    server if address_map[original_dst] == client else client
                )
            elif original_dst not in address_map:
                address_map[original_dst] = (
                    server if address_map[original_src] == client else client
                )
            network.src = address_map[original_src]
            network.dst = address_map[original_dst]
            if IP in packet:
                del packet[IP].chksum
            if TCP in packet:
                del packet[TCP].chksum
            if UDP in packet:
                del packet[UDP].chksum
        data = bytes(packet)
        timestamp = row.timestamp_ns if row.source == "online_public_corpus" and \
            config.preserve_public_timestamps else target + row.timestamp_ns - first
        result.append(PacketRow(case_id, timestamp, data, max(row.wirelen, len(data)), row.source))
    return result


def _case_classification(expected: dict[str, Any]) -> str:
    """Classify reviewed evidence without treating missing evidence as a pass."""
    if expected.get("findings"):
        return "error_prone"
    flows = expected.get("flows") or []
    sessions = expected.get("sessions") or []
    handshakes = expected.get("handshakes") or []
    certificates = expected.get("certificates") or []
    if any(flow.get("reconstruction_quality") in {"incomplete", "conflicting"}
           for flow in flows):
        return "error_prone"
    for session in sessions:
        upgrade = session.get("explicit_upgrade") or {}
        if upgrade.get("state") in {"plaintext_fallback", "violation"} or \
                upgrade.get("downgrade_consistent") is True:
            return "error_prone"
    if any(handshake.get("evidence_state") in {"incomplete", "conflicting"}
           or handshake.get("established") is False for handshake in handshakes):
        return "error_prone"
    if any(certificate.get("syntax_valid") is False for certificate in certificates):
        return "error_prone"

    complete_flow = any(flow.get("reconstruction_quality") == "complete"
                        and flow.get("proto") == "tcp" for flow in flows)
    established_tls = any(handshake.get("established") is True
                          and handshake.get("evidence_state") in {"observed", "verified"}
                          for handshake in handshakes)
    established_upgrade = any(
        (session.get("explicit_upgrade") or {}).get("state") == "tls_established"
        for session in sessions
    )
    if complete_flow and (established_tls or established_upgrade):
        return "successful"
    return "neutral"


def _balance_packets(rows: list[PacketRow], classifications: dict[str, str],
                     first_replica_index: int, config: Config,
                     ) -> tuple[list[PacketRow], dict[str, Any]]:
    by_case: dict[str, list[PacketRow]] = {}
    for row in rows:
        by_case.setdefault(row.case_id, []).append(row)
    error_count = sum(len(by_case.get(case_id, [])) for case_id, category
                      in classifications.items() if category == "error_prone")
    successful_count = sum(len(by_case.get(case_id, [])) for case_id, category
                           in classifications.items() if category == "successful")
    neutral_count = len(rows) - error_count - successful_count
    target = math.ceil(error_count * config.successful_to_error_packet_ratio)
    replicas = 0
    if config.balance_successful_packets and successful_count < target:
        candidates = sorted(case_id for case_id, category in classifications.items()
                            if category == "successful" and by_case.get(case_id))
        if not candidates:
            raise DemoError("packet balancing requires at least one successful case")
        while successful_count < target:
            case_id = candidates[replicas % len(candidates)]
            template = [
                PacketRow(row.case_id, row.timestamp_ns, row.data, row.wirelen,
                          "successful_replica")
                for row in by_case[case_id]
            ]
            replica = _isolate_case(template, case_id,
                                    first_replica_index + replicas, config)
            rows.extend(replica)
            successful_count += len(replica)
            replicas += 1
    achieved = successful_count / error_count if error_count else None
    return rows, {
        "enabled": config.balance_successful_packets,
        "requested_successful_to_error_ratio": config.successful_to_error_packet_ratio,
        "target_successful_packet_count": target,
        "successful_packet_count": successful_count,
        "error_prone_packet_count": error_count,
        "neutral_packet_count": neutral_count,
        "successful_replica_count": replicas,
        "balance_overshoot_packet_count": max(0, successful_count - target),
        "achieved_successful_to_error_ratio": achieved,
    }


def _address(network_text: str, index: int) -> str:
    network = ipaddress.ip_network(network_text, strict=True)
    value = int(network.network_address) + index + 1
    if value >= int(network.broadcast_address):
        raise DemoError(f"{network} has too few usable addresses")
    return str(ipaddress.ip_address(value))


def _record(version: int, payload: bytes) -> bytes:
    return b"\x16" + struct.pack("!HH", min(version, 0x0303), len(payload)) + payload


def _handshake(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + _u24(len(body)) + body


def _u24(value: int) -> bytes:
    return value.to_bytes(3, "big")


def _write_pcapng(path: Path, rows: list[PacketRow], *, annotate: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        with temporary.open("wb") as stream:
            _block(stream, 0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
            options = _option(9, b"\x09") + struct.pack("<HH", 0, 0)
            _block(stream, 1, struct.pack("<HHI", 1, 0, 262144) + options)
            for row in rows:
                header = struct.pack("<IIIII", 0, row.timestamp_ns >> 32,
                                     row.timestamp_ns & 0xFFFFFFFF, len(row.data), row.wirelen)
                data = row.data + b"\x00" * ((-len(row.data)) % 4)
                options = _option(1, f"SecureMail fixture: {row.case_id}".encode()) \
                    + struct.pack("<HH", 0, 0) if annotate else b""
                _block(stream, 6, header + data + options)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _option(code: int, value: bytes) -> bytes:
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * ((-len(value)) % 4)


def _block(stream: BinaryIO, kind: int, body: bytes) -> None:
    body += b"\x00" * ((-len(body)) % 4)
    length = len(body) + 12
    stream.write(struct.pack("<II", kind, length) + body + struct.pack("<I", length))


def _ranges(values: list[int]) -> list[dict[str, int]]:
    if not values:
        return []
    result, start, previous = [], values[0], values[0]
    for value in values[1:]:
        if value == previous + 1:
            previous = value
            continue
        result.append({"start": start, "end": previous})
        start = previous = value
    result.append({"start": start, "end": previous})
    return result


def _prepare_outputs(capture: Path, manifest: Path, replace: bool) -> None:
    existing = [str(path) for path in (capture, manifest) if path.exists()]
    if existing and not replace:
        raise DemoError("output exists; use --replace-existing: " + ", ".join(existing))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(fd)
    temporary = Path(name)
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise DemoError(f"JSON must be an object: {path}")
    return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _timestamp_ns(value: str) -> int:
    return int(_datetime(value).timestamp() * 1_000_000_000)


def _config_payload(config: Config) -> dict[str, Any]:
    payload = asdict(config)
    for key in ("contract_root", "output_capture", "output_manifest", "cache_root"):
        payload[key] = str(payload[key]) if payload[key] is not None else None
    payload["include"], payload["exclude"] = list(config.include), list(config.exclude)
    return payload


def _load_config(path: Path | None) -> Config:
    base = default_config()
    if path is None:
        return base
    payload = _read_object(path)
    unknown = sorted(set(payload) - set(asdict(base)))
    if unknown:
        raise DemoError("unknown configuration keys: " + ", ".join(unknown))
    values = _config_payload(base)
    values.update(payload)
    for key in ("contract_root", "output_capture", "output_manifest", "cache_root"):
        if values[key] is None:
            continue
        candidate = Path(values[key]).expanduser()
        values[key] = candidate if candidate.is_absolute() else (path.parent / candidate).resolve()
    values["include"], values["exclude"] = tuple(values["include"]), tuple(values["exclude"])
    return Config(**values)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--include", action="append")
    parser.add_argument("--exclude", action="append")
    parser.add_argument("--public-corpus-mode", choices=("online", "synthetic"))
    parser.add_argument("--successful-to-error-packet-ratio", type=float)
    parser.add_argument("--no-balance-successful-packets", action="store_true")
    parser.add_argument("--replace-existing", action="store_true")
    parser.add_argument("--print-default-config", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.print_default_config:
        print(json.dumps(_config_payload(default_config()), indent=2, sort_keys=True))
        return 0
    try:
        config = _load_config(args.config)
        values = asdict(config)
        for key, value in {
            "output_capture": args.out, "output_manifest": args.manifest,
            "include": tuple(args.include) if args.include else None,
            "exclude": tuple(args.exclude) if args.exclude else None,
            "public_corpus_mode": args.public_corpus_mode,
            "successful_to_error_packet_ratio": args.successful_to_error_packet_ratio,
        }.items():
            if value is not None:
                values[key] = value
        if args.replace_existing:
            values["replace_existing"] = True
        if args.no_balance_successful_packets:
            values["balance_successful_packets"] = False
        result = build(Config(**values))
    except (DemoError, OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Wrote {result.packet_count} packets covering {len(result.case_ids)} test cases "
          f"to {result.output_capture}")
    print(f"Manifest: {result.output_manifest}")
    print(f"SHA-256: {result.capture_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
