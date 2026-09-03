"""Generate the Step 0 empty fixture: unrelated non-mail packets via Scapy."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from scapy.config import conf
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapNgWriter

conf.verb = 0

ROOT = Path(__file__).resolve().parents[3]
OUT_DIR = ROOT / "tests" / "fixtures" / "empty"
GENERATOR = "tests/fixtures/generators/empty_capture.py"


def build_packets() -> list[object]:
    """A handful of unrelated packets. No SMTP/IMAP/POP3."""

    return [
        Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            hwsrc="02:00:00:00:00:01",
            hwdst="00:00:00:00:00:00",
            psrc="192.0.2.1",
            pdst="192.0.2.2",
            op=1,
        ),
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.1", dst="192.0.2.2")
        / ICMP(),
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.1", dst="192.0.2.53")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.test")),
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="192.0.2.80")
        / TCP(sport=49152, dport=80, flags="S"),
        Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
        / IP(src="192.0.2.80", dst="192.0.2.10")
        / TCP(sport=80, dport=49152, flags="RA"),
    ]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def write_capture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    packets = build_packets()
    with PcapNgWriter(str(path)) as writer:
        for packet in packets:
            writer.write(bytes(packet))


def write_provenance(path: Path, capture_sha256: str, scapy_version: str) -> None:
    payload = {
        "source": "scapy",
        "generator": f"{GENERATOR} --out tests/fixtures/empty/capture.pcapng",
        "tool_versions": {"scapy": scapy_version},
        "sha256": capture_sha256,
        "created_at": "2026-01-01T00:00:00Z",
        "notes": (
            "Trivial unrelated packets (ARP, ICMP, DNS, TCP/80) used only to prove "
            "the Step 0 analyze pipeline runs end to end. Not mail-protocol evidence."
        ),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=OUT_DIR / "capture.pcapng")
    args = parser.parse_args()
    write_capture(args.out)
    digest = sha256_file(args.out)
    import scapy

    write_provenance(args.out.parent / "provenance.json", digest, scapy.__version__)
    print(f"wrote {args.out} sha256={digest}")


if __name__ == "__main__":
    main()
