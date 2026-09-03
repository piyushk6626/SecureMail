"""Lab-capture a complete plaintext SMTP session on a Docker bridge."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tcp_common import ROOT, sha256_file  # noqa: E402

GENERATOR = "tests/fixtures/generators/lab_smtp_tcp_baseline.py"
CASE_ID = "tcp_smtp_clean_baseline"
DEBIAN_DIGEST = "sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132"
PYTHON_IMAGE = (
    "python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3"
)
TSHARK_IMAGE = "securemail/tshark:step0"
SERVER_NAME = "securemail-step1-smtp"
CAP_NAME = "securemail-step1-dumpcap"
NET_NAME = "securemail-step1-tcp-lab"

SERVER_SCRIPT = r"""
import smtpd
import asyncore

class Sink(smtpd.SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        return

Sink(("0.0.0.0", 25), None)
asyncore.loop()
"""

CLIENT_SCRIPT = r"""
import smtplib
import sys
from email.message import EmailMessage

host = sys.argv[1]
message = EmailMessage()
message["From"] = "a@example.test"
message["To"] = "b@example.test"
message["Subject"] = "securemail-tcp-baseline"
message.set_content("hello from the Step 1 lab baseline\n")
with smtplib.SMTP(host, 25, timeout=15) as client:
    client.send_message(message)
"""


def _run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=check, capture_output=True, text=True)


def _cleanup() -> None:
    _run(["docker", "rm", "-f", CAP_NAME], check=False)
    _run(["docker", "rm", "-f", SERVER_NAME], check=False)
    _run(["docker", "network", "rm", NET_NAME], check=False)


def _docker_output(argv: list[str]) -> str:
    completed = _run(argv)
    return completed.stdout.strip()


def generate() -> Path:
    if shutil.which("docker") is None:
        raise RuntimeError("docker is required to generate the lab SMTP baseline")
    out_dir = ROOT / "tests" / "fixtures" / CASE_ID
    out_dir.mkdir(parents=True, exist_ok=True)
    capture = out_dir / "capture.pcapng"
    _cleanup()
    tmp = Path(tempfile.mkdtemp(prefix="securemail-lab-smtp-"))
    try:
        os.chmod(tmp, 0o1777)
        _run(["docker", "network", "create", NET_NAME])
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                SERVER_NAME,
                "--network",
                NET_NAME,
                PYTHON_IMAGE,
                "python",
                "-c",
                SERVER_SCRIPT,
            ]
        )
        time.sleep(1)
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                CAP_NAME,
                "--network",
                f"container:{SERVER_NAME}",
                "--user",
                "0",
                "--cap-add",
                "NET_RAW",
                "--cap-add",
                "NET_ADMIN",
                "--mount",
                f"type=bind,src={tmp},dst=/data/out",
                "--entrypoint",
                "dumpcap",
                TSHARK_IMAGE,
                "-i",
                "eth0",
                "-f",
                "tcp port 25",
                "-q",
                "-w",
                "/data/out/capture.pcapng",
            ]
        )
        time.sleep(1)
        inspect = _run(["docker", "inspect", "-f", "{{.State.Running}}", CAP_NAME])
        if inspect.stdout.strip() != "true":
            logs = _run(["docker", "logs", CAP_NAME], check=False)
            raise RuntimeError(f"dumpcap sidecar failed:\n{logs.stdout}\n{logs.stderr}")
        server_ip = _docker_output(
            [
                "docker",
                "inspect",
                "-f",
                "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                SERVER_NAME,
            ]
        )
        client = _run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                NET_NAME,
                PYTHON_IMAGE,
                "python",
                "-c",
                CLIENT_SCRIPT,
                server_ip,
            ]
        )
        if client.returncode != 0:
            raise RuntimeError(f"SMTP client failed:\n{client.stdout}\n{client.stderr}")
        time.sleep(1)
        _run(["docker", "stop", "-t", "2", CAP_NAME], check=False)
        captured = tmp / "capture.pcapng"
        if not captured.is_file() or captured.stat().st_size < 64:
            logs = _run(["docker", "logs", CAP_NAME], check=False)
            raise RuntimeError(f"lab capture missing or too small:\n{logs.stdout}\n{logs.stderr}")
        capture.write_bytes(captured.read_bytes())
    finally:
        _cleanup()
        shutil.rmtree(tmp, ignore_errors=True)

    dumpcap_version = _docker_output(
        ["docker", "run", "--rm", "--entrypoint", "dumpcap", TSHARK_IMAGE, "-v"]
    )
    python_version = _docker_output(
        [
            "docker",
            "run",
            "--rm",
            PYTHON_IMAGE,
            "python",
            "-c",
            "import sys; print(sys.version.split()[0])",
        ]
    )
    digest = sha256_file(capture)
    payload = {
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "generator": (
            f"{GENERATOR} --out tests/fixtures/{CASE_ID}/capture.pcapng "
            f"(docker network {NET_NAME}; python SMTP server+client; "
            f"dumpcap sidecar --network container:{SERVER_NAME})"
        ),
        "notes": (
            "Lab baseline: complete plaintext SMTP on a Docker bridge using the "
            "Linux TCP stack. dumpcap (Wireshark) shares the server netns "
            "(tcpdump-sidecar equivalent). Not a public corpus sample."
        ),
        "sha256": digest,
        "source": "lab",
        "tool_versions": {
            "debian_base_digest": DEBIAN_DIGEST,
            "dumpcap": dumpcap_version.splitlines()[0] if dumpcap_version else "unknown",
            "python": python_version,
            "python_image": PYTHON_IMAGE,
            "tshark_image": TSHARK_IMAGE,
        },
    }
    (out_dir / "provenance.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return capture


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "tests" / "fixtures" / CASE_ID / "capture.pcapng",
    )
    args = parser.parse_args()
    capture = generate()
    if args.out.resolve() != capture.resolve():
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(capture.read_bytes())
        capture = args.out
    print(f"wrote {capture} sha256={sha256_file(capture)}")


if __name__ == "__main__":
    main()
