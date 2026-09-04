"""Import public-corpus TLS 1.2 and TLS 1.3 regression slices."""

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

GENERATOR = "tests/fixtures/generators/import_tls_public_corpus.py"
TSHARK_IMAGE = "securemail/tshark:step0"
USER_AGENT = (
    "Mozilla/5.0 (compatible; SecureMail-fixture-import; +https://weberblog.net/the-ultimate-pcap/)"
)

SOURCE_URL = "https://weberblog.net/wp-content/uploads/2020/02/The-Ultimate-PCAP.pcapng.gz"
SOURCE_SHA256 = "96359b8119ec53f347af4b7e55727d020d2ff60f30b0906da350b8564f49f49c"
SOURCE_URLS = (
    SOURCE_URL,
    "https://weberblog.net/wp-content/uploads/2026/07/The-Ultimate-PCAP.pcapng.gz",
    "https://weberblog.net/wp-content/uploads/2024/06/The-Ultimate-PCAP.pcapng.gz",
)

CASES: dict[str, dict[str, str]] = {
    "tls12_public_corpus": {
        "display_filter": (
            "tls.handshake.type == 2 and tls.handshake.version == 0x0303 "
            "and not tls.handshake.extensions.supported_version"
        ),
        "notes": (
            "Public-corpus TLS 1.2 handshake slice from The Ultimate PCAP "
            "(weberblog.net). Regression only, not sole proof of a rule."
        ),
    },
    "tls13_public_corpus": {
        "display_filter": (
            "tls.handshake.type == 2 and tls.handshake.extensions.supported_version == 0x0304"
        ),
        "notes": (
            "Public-corpus TLS 1.3 handshake slice from The Ultimate PCAP "
            "(weberblog.net). Regression only, not sole proof of a rule."
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


def _download_ultimate_pcap(dest: Path) -> tuple[bytes, str]:
    last_error: Exception | None = None
    for url in SOURCE_URLS:
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
    with tempfile.TemporaryDirectory(prefix="securemail-tls-corpus-extract-") as tmp:
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
        unique_streams: list[str] = []
        for stream in streams:
            if stream not in unique_streams:
                unique_streams.append(stream)
        chosen: str | None = None
        for stream in unique_streams:
            syn = _docker_tool(
                tmp_path,
                "tshark",
                "-n",
                "-r",
                f"/data/{source.name}",
                "-Y",
                f"tcp.stream == {stream} and tcp.flags.syn==1 and tcp.flags.ack==0",
                "-T",
                "fields",
                "-e",
                "frame.number",
            )
            if syn.stdout.strip():
                chosen = stream
                break
        if chosen is None:
            chosen = unique_streams[0]
        _docker_tool(
            tmp_path,
            "tshark",
            "-n",
            "-r",
            f"/data/{source.name}",
            "-Y",
            f"tcp.stream == {chosen}",
            "-w",
            "/data/slice.pcapng",
        )
        _docker_tool(tmp_path, "editcap", "-T", "ether", "/data/slice.pcapng", "/data/ether.pcapng")
        _docker_tool(tmp_path, "editcap", "-F", "pcap", "/data/ether.pcapng", "/data/slice.pcap")
        _docker_tool(tmp_path, "editcap", "-F", "pcapng", "/data/slice.pcap", "/data/out.pcapng")
        dest.write_bytes((tmp_path / "out.pcapng").read_bytes())


def generate_case(case_id: str) -> Path:
    spec = CASES[case_id]
    out_dir = ROOT / "tests" / "fixtures" / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    capture = out_dir / "capture.pcapng"
    with tempfile.TemporaryDirectory(prefix="securemail-tls-ultimate-") as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / "The-Ultimate-PCAP.pcapng.gz"
        payload, url = _download_ultimate_pcap(archive)
        source_digest = hashlib.sha256(payload).hexdigest()
        if source_digest != SOURCE_SHA256:
            raise RuntimeError(
                f"{case_id} Ultimate PCAP hash mismatch: got {source_digest}, "
                f"expected {SOURCE_SHA256}"
            )
        unpacked = _decompress_if_gzip(archive)
        _extract_stream(unpacked, capture, spec["display_filter"])
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
