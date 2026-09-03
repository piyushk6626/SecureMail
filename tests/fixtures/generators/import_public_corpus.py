"""Import public-corpus SMTP/IMAP regression captures into pcapng fixtures."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tcp_common import ROOT, sha256_file  # noqa: E402

GENERATOR = "tests/fixtures/generators/import_public_corpus.py"
TSHARK_IMAGE = "securemail/tshark:step0"
USER_AGENT = (
    "Mozilla/5.0 (compatible; SecureMail-fixture-import; +https://weberblog.net/the-ultimate-pcap/)"
)

CASES: dict[str, dict[str, str]] = {
    "smtp_public_corpus": {
        "url": (
            "https://wiki.wireshark.org/uploads/__moin_import__/attachments/"
            "SampleCaptures/smtp.pcap"
        ),
        "license": (
            "Wireshark wiki SampleCaptures contribution; used as an independent "
            "regression cross-check only, not as sole proof of a rule."
        ),
        "source_sha256": "17ad230db1b6fd5dd18eb311092df1cf6eb162054bdb47697b89bef5a86a47ab",
        "source_filename": "smtp.pcap",
        "notes": (
            "Public Wireshark SampleCaptures smtp.pcap (SMTP on TCP/25). Converted "
            "to pcapng with editcap -F pcapng; packets are otherwise unmodified."
        ),
    },
    "imap_public_corpus": {
        "url": (
            "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/imap.cap"
        ),
        "license": (
            "Wireshark wiki SampleCaptures / IMAP page contribution; used as an "
            "independent regression cross-check only, not as sole proof of a rule."
        ),
        "source_sha256": "fa9a9bcca7b7f2943d740d46b075565b0dbbcc0f60ab321bf577a7be9724b5a8",
        "source_filename": "imap.cap",
        "notes": (
            "Public Wireshark SampleCaptures imap.cap (IMAP on TCP/143). Converted "
            "to pcapng with editcap -F pcapng; packets are otherwise unmodified."
        ),
    },
}

# The file is published at the 2020/02 WordPress path and updated in place.
STARTTLS_SOURCE_URL = "https://weberblog.net/wp-content/uploads/2020/02/The-Ultimate-PCAP.pcapng.gz"
STARTTLS_SOURCE_SHA256 = "96359b8119ec53f347af4b7e55727d020d2ff60f30b0906da350b8564f49f49c"
STARTTLS_SOURCE_URLS = (
    STARTTLS_SOURCE_URL,
    "https://weberblog.net/wp-content/uploads/2026/07/The-Ultimate-PCAP.pcapng.gz",
    "https://weberblog.net/wp-content/uploads/2024/06/The-Ultimate-PCAP.pcapng.gz",
)

STARTTLS_CASES: dict[str, dict[str, str]] = {
    "smtp_starttls_public_corpus": {
        # TShark's SMTP dissector stores STARTTLS as the 4-character verb STAR.
        "command_filter": 'smtp.req.command == "STAR" and tcp.port == 587',
        "notes": (
            "Public-corpus SMTP STARTTLS stream slice extracted from The Ultimate "
            "PCAP (weberblog.net). Regression only, not sole proof of the rule."
        ),
    },
    "imap_starttls_public_corpus": {
        "command_filter": 'imap.request.command == "STARTTLS"',
        "notes": (
            "Public-corpus IMAP STARTTLS stream slice extracted from The Ultimate "
            "PCAP (weberblog.net). Regression only, not sole proof of the rule."
        ),
    },
    "pop3_stls_public_corpus": {
        "command_filter": 'pop.request.command == "STLS"',
        "notes": (
            "Public-corpus POP3 STLS stream slice extracted from The Ultimate "
            "PCAP (weberblog.net). Regression only, not sole proof of the rule."
        ),
    },
}


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=True, capture_output=True, text=True)


def _docker_tool(tmp_path: Path, entrypoint: str, *args: str) -> subprocess.CompletedProcess[str]:
    return _run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--user",
            "0",
            "--mount",
            f"type=bind,src={tmp_path},dst=/data",
            "--entrypoint",
            entrypoint,
            TSHARK_IMAGE,
            *args,
        ]
    )


def _convert(source: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="securemail-corpus-") as tmp:
        tmp_path = Path(tmp)
        shutil.copy2(source, tmp_path / source.name)
        _run(
            [
                "docker",
                "run",
                "--rm",
                "--network=none",
                "--user",
                "0",
                "--mount",
                f"type=bind,src={tmp_path},dst=/data",
                "--entrypoint",
                "editcap",
                TSHARK_IMAGE,
                "-F",
                "pcapng",
                f"/data/{source.name}",
                "/data/capture.pcapng",
            ]
        )
        dest.write_bytes((tmp_path / "capture.pcapng").read_bytes())


def _download_ultimate_pcap(dest: Path) -> tuple[bytes, str]:
    last_error: Exception | None = None
    for url in STARTTLS_SOURCE_URLS:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
                payload = response.read()
        except OSError as exc:
            last_error = exc
            continue
        if len(payload) < 1024 or not (
            payload.startswith(b"\x1f\x8b") or payload.startswith(b"\x0a\x0d\x0d\x0a")
        ):
            last_error = RuntimeError(f"{url} did not return gzip or pcapng bytes")
            continue
        dest.write_bytes(payload)
        return payload, url
    raise RuntimeError(f"could not download The Ultimate PCAP: {last_error}")


def _decompress_if_gzip(path: Path) -> Path:
    header = path.read_bytes()[:2]
    if header != b"\x1f\x8b":
        return path
    out = path.with_suffix("")
    out.write_bytes(gzip.decompress(path.read_bytes()))
    return out


def _extract_stream(source: Path, dest: Path, display_filter: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="securemail-corpus-extract-") as tmp:
        tmp_path = Path(tmp)
        shutil.copy2(source, tmp_path / source.name)
        listed = _docker_tool(
            tmp_path,
            "tshark",
            "-n",
            "-r",
            f"/data/{source.name}",
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-e",
            "tcp.stream",
        )
        streams = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
        if not streams:
            raise RuntimeError(f"no packets matched {display_filter} in {source.name}")
        stream = streams[0]
        _docker_tool(
            tmp_path,
            "tshark",
            "-n",
            "-r",
            f"/data/{source.name}",
            "-Y",
            f"tcp.stream == {stream}",
            "-w",
            "/data/slice.pcapng",
        )
        # The Ultimate PCAP is a merge of hundreds of interfaces with mixed
        # snaplens. Flatten to Ethernet/pcap then back to pcapng so Zeek can read it.
        _docker_tool(tmp_path, "editcap", "-T", "ether", "/data/slice.pcapng", "/data/ether.pcapng")
        _docker_tool(tmp_path, "editcap", "-F", "pcap", "/data/ether.pcapng", "/data/slice.pcap")
        _docker_tool(tmp_path, "editcap", "-F", "pcapng", "/data/slice.pcap", "/data/out.pcapng")
        dest.write_bytes((tmp_path / "out.pcapng").read_bytes())


def generate_starttls_case(case_id: str) -> Path:
    spec = STARTTLS_CASES[case_id]
    out_dir = ROOT / "tests" / "fixtures" / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    capture = out_dir / "capture.pcapng"
    with tempfile.TemporaryDirectory(prefix="securemail-ultimate-") as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / "The-Ultimate-PCAP.pcapng.gz"
        payload, url = _download_ultimate_pcap(archive)
        source_digest = hashlib.sha256(payload).hexdigest()
        if source_digest != STARTTLS_SOURCE_SHA256:
            raise RuntimeError(
                f"{case_id} Ultimate PCAP hash mismatch: got {source_digest}, "
                f"expected {STARTTLS_SOURCE_SHA256}"
            )
        unpacked = _decompress_if_gzip(archive)
        _extract_stream(unpacked, capture, spec["command_filter"])
    capture_digest = sha256_file(capture)
    tshark_version = _run(
        ["docker", "run", "--rm", "--entrypoint", "tshark", TSHARK_IMAGE, "-v"]
    ).stdout.strip()
    record = {
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "conversion": (
            "tshark stream extract; editcap -T ether; editcap -F pcap; "
            f"editcap -F pcapng -> tests/fixtures/{case_id}/capture.pcapng"
        ),
        "generator": f"{GENERATOR} --case {case_id}",
        "license": (
            "The Ultimate PCAP by Johannes Weber (weberblog.net); used as an "
            "independent regression cross-check only, not as sole proof of a rule."
        ),
        "notes": spec["notes"],
        "sha256": capture_digest,
        "source": "public_corpus",
        "source_sha256": source_digest,
        "source_url": url,
        "tool_versions": {
            "tshark": tshark_version.splitlines()[0] if tshark_version else "unknown",
            "tshark_image": TSHARK_IMAGE,
        },
    }
    (out_dir / "provenance.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return capture


def generate_case(case_id: str) -> Path:
    if case_id in STARTTLS_CASES:
        return generate_starttls_case(case_id)
    spec = CASES[case_id]
    out_dir = ROOT / "tests" / "fixtures" / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    capture = out_dir / "capture.pcapng"
    request = urllib.request.Request(spec["url"], headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        payload = response.read()
    digest = hashlib.sha256(payload).hexdigest()
    if digest != spec["source_sha256"]:
        raise RuntimeError(
            f"{case_id} source hash mismatch: got {digest}, expected {spec['source_sha256']}"
        )
    with tempfile.TemporaryDirectory(prefix="securemail-corpus-src-") as tmp:
        source = Path(tmp) / spec["source_filename"]
        source.write_bytes(payload)
        _convert(source, capture)
    capture_digest = sha256_file(capture)
    editcap_version = _run(
        ["docker", "run", "--rm", "--entrypoint", "editcap", TSHARK_IMAGE, "-v"]
    ).stdout.strip()
    record = {
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "conversion": "editcap -F pcapng <source> tests/fixtures/<case_id>/capture.pcapng",
        "generator": f"{GENERATOR} --case {case_id}",
        "license": spec["license"],
        "notes": spec["notes"],
        "sha256": capture_digest,
        "source": "public_corpus",
        "source_sha256": spec["source_sha256"],
        "source_url": spec["url"],
        "tool_versions": {
            "editcap": editcap_version.splitlines()[0] if editcap_version else "unknown",
            "tshark_image": TSHARK_IMAGE,
        },
    }
    (out_dir / "provenance.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return capture


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    choices = ["all", *sorted({*CASES, *STARTTLS_CASES})]
    parser.add_argument("--case", choices=choices, default="all")
    args = parser.parse_args()
    if args.case == "all":
        selected = [*CASES, *STARTTLS_CASES]
    else:
        selected = [args.case]
    for case_id in selected:
        capture = generate_case(case_id)
        print(f"wrote {capture} sha256={sha256_file(capture)}")


if __name__ == "__main__":
    main()
