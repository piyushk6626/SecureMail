"""Import a public-corpus TLS handshake that carries a full certificate chain."""

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

GENERATOR = "tests/fixtures/generators/import_cert_public_corpus.py"
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

CASE_ID = "cert_chain_public_corpus"
DISPLAY_FILTER = (
    "tls.handshake.type == 11 and tls.handshake.version == 0x0303 "
    "and not tls.handshake.extensions.supported_version"
)
NOTES = (
    "Public-corpus TLS 1.2 handshake with a multi-certificate chain from "
    "The Ultimate PCAP (weberblog.net). Regression only, not sole proof of a rule."
)


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


def _choose_chain_stream(tmp_path: Path, source_name: str) -> str:
    listed = _docker_tool(
        tmp_path,
        "tshark",
        "-n",
        "-r",
        f"/data/{source_name}",
        "-Y",
        DISPLAY_FILTER,
        "-T",
        "fields",
        "-E",
        "occurrence=a",
        "-e",
        "tcp.stream",
        "-e",
        "tls.handshake.certificate",
    )
    counts: dict[str, int] = {}
    for line in listed.stdout.splitlines():
        if not line.strip():
            continue
        stream, _, rest = line.partition("\t")
        stream = stream.strip()
        if not stream:
            continue
        certs = [part for part in rest.split(",") if part.strip()]
        counts[stream] = max(counts.get(stream, 0), len(certs))
    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    for stream, count in ranked:
        if count < 2:
            continue
        syn = _docker_tool(
            tmp_path,
            "tshark",
            "-n",
            "-r",
            f"/data/{source_name}",
            "-Y",
            f"tcp.stream == {stream} and tcp.flags.syn==1 and tcp.flags.ack==0",
            "-T",
            "fields",
            "-e",
            "frame.number",
        )
        if syn.stdout.strip():
            return stream
    if ranked and ranked[0][1] >= 2:
        return ranked[0][0]
    raise RuntimeError("no TLS 1.2 stream with a multi-certificate chain was found")


def generate_case() -> Path:
    out_dir = ROOT / "tests" / "fixtures" / CASE_ID
    out_dir.mkdir(parents=True, exist_ok=True)
    capture = out_dir / "capture.pcapng"
    with tempfile.TemporaryDirectory(prefix="securemail-cert-ultimate-") as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / "The-Ultimate-PCAP.pcapng.gz"
        payload, url = _download_ultimate_pcap(archive)
        source_digest = hashlib.sha256(payload).hexdigest()
        if source_digest != SOURCE_SHA256:
            raise RuntimeError(
                f"{CASE_ID} Ultimate PCAP hash mismatch: got {source_digest}, "
                f"expected {SOURCE_SHA256}"
            )
        unpacked = _decompress_if_gzip(archive)
        source_name = unpacked.name
        if unpacked.resolve() != (tmp_path / source_name).resolve():
            shutil.copy2(unpacked, tmp_path / source_name)
        stream = _choose_chain_stream(tmp_path, source_name)
        _docker_tool(
            tmp_path,
            "tshark",
            "-n",
            "-r",
            f"/data/{source_name}",
            "-Y",
            f"tcp.stream == {stream}",
            "-w",
            "/data/slice.pcapng",
        )
        _docker_tool(tmp_path, "editcap", "-T", "ether", "/data/slice.pcapng", "/data/ether.pcapng")
        _docker_tool(tmp_path, "editcap", "-F", "pcap", "/data/ether.pcapng", "/data/slice.pcap")
        _docker_tool(tmp_path, "editcap", "-F", "pcapng", "/data/slice.pcap", "/data/out.pcapng")
        capture.write_bytes((tmp_path / "out.pcapng").read_bytes())
    capture_digest = sha256_file(capture)
    tshark_version = _run(
        ["docker", "run", "--rm", "--entrypoint", "tshark", TSHARK_IMAGE, "-v"]
    ).stdout.strip()
    record = {
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "conversion": (
            "tshark stream extract of a TLS 1.2 certificate chain; editcap -T ether; "
            f"editcap -F pcap; editcap -F pcapng -> tests/fixtures/{CASE_ID}/capture.pcapng"
        ),
        "generator": f"{GENERATOR} --case {CASE_ID}",
        "license": (
            "The Ultimate PCAP by Johannes Weber (weberblog.net); used as an "
            "independent regression cross-check only, not as sole proof of a rule."
        ),
        "notes": NOTES,
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
    parser.add_argument("--case", choices=["all", CASE_ID], default="all")
    parser.parse_args()
    capture = generate_case()
    print(f"wrote {capture} sha256={sha256_file(capture)}")


if __name__ == "__main__":
    main()
