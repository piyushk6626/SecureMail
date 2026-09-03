"""Import public-corpus SMTP/IMAP regression captures into pcapng fixtures."""

from __future__ import annotations

import argparse
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
USER_AGENT = "SecureMail-fixture-import"

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


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=True, capture_output=True, text=True)


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


def generate_case(case_id: str) -> Path:
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
    parser.add_argument("--case", choices=["all", *sorted(CASES)], default="all")
    args = parser.parse_args()
    selected = list(CASES) if args.case == "all" else [args.case]
    for case_id in selected:
        capture = generate_case(case_id)
        print(f"wrote {capture} sha256={sha256_file(capture)}")


if __name__ == "__main__":
    main()
