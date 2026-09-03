"""Lab-capture plaintext SMTP/587, IMAP/143, and POP3/110 on a Docker bridge."""

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

GENERATOR = "tests/fixtures/generators/lab_mail_protocol_captures.py"
DEBIAN_DIGEST = "sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132"
PYTHON_IMAGE = (
    "python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3"
)
TSHARK_IMAGE = "securemail/tshark:step0"

SMTP_SERVER = r"""
import smtpd
import asyncore

class Sink(smtpd.SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        return

Sink(("0.0.0.0", 587), None)
asyncore.loop()
"""

SMTP_CLIENT = r"""
import smtplib
import sys
from email.message import EmailMessage

host = sys.argv[1]
message = EmailMessage()
message["From"] = "a@example.test"
message["To"] = "b@example.test"
message["Subject"] = "securemail-step2-smtp587"
message.set_content("hello from the Step 2 SMTP submission lab\n")
with smtplib.SMTP(host, 587, timeout=15) as client:
    client.send_message(message)
"""

IMAP_SERVER = r"""
import asyncio

async def handle(reader, writer):
    writer.write(b"* OK IMAP4rev1 ready\r\n")
    await writer.drain()
    while True:
        line = await reader.readline()
        if not line:
            break
        decoded = line.decode("ascii", "replace").strip()
        parts = decoded.split()
        if len(parts) >= 2 and parts[1].upper() == "CAPABILITY":
            tag = parts[0]
            writer.write(b"* CAPABILITY IMAP4rev1 STARTTLS\r\n")
            writer.write(f"{tag} OK CAPABILITY completed\r\n".encode("ascii"))
            await writer.drain()
        elif len(parts) >= 2 and parts[1].upper() == "LOGOUT":
            tag = parts[0]
            writer.write(b"* BYE logging out\r\n")
            writer.write(f"{tag} OK LOGOUT completed\r\n".encode("ascii"))
            await writer.drain()
            break
        elif len(parts) >= 2 and parts[1].upper() == "NOOP":
            tag = parts[0]
            writer.write(f"{tag} OK NOOP completed\r\n".encode("ascii"))
            await writer.drain()
        else:
            tag = parts[0] if parts else "*"
            writer.write(f"{tag} BAD unknown\r\n".encode("ascii"))
            await writer.drain()
    writer.close()
    await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", 143)
    async with server:
        await server.serve_forever()

asyncio.run(main())
"""

IMAP_CLIENT = r"""
import imaplib
import sys

host = sys.argv[1]
client = imaplib.IMAP4(host, 143)
client.capability()
client.logout()
"""

POP3_SERVER = r"""
import asyncio

async def handle(reader, writer):
    writer.write(b"+OK POP3 ready\r\n")
    await writer.drain()
    while True:
        line = await reader.readline()
        if not line:
            break
        decoded = line.decode("ascii", "replace").strip()
        command = decoded.split(" ", 1)[0].upper()
        if command == "CAPA":
            writer.write(b"+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n")
            await writer.drain()
        elif command == "QUIT":
            writer.write(b"+OK Bye\r\n")
            await writer.drain()
            break
        elif command == "NOOP":
            writer.write(b"+OK\r\n")
            await writer.drain()
        else:
            writer.write(b"-ERR unknown\r\n")
            await writer.drain()
    writer.close()
    await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", 110)
    async with server:
        await server.serve_forever()

asyncio.run(main())
"""

POP3_CLIENT = r"""
import poplib
import sys

host = sys.argv[1]
client = poplib.POP3(host, 110, timeout=15)
client.capa()
client.quit()
"""

CASES: dict[str, dict[str, str | int]] = {
    "smtp_submission_port": {
        "port": 587,
        "server": SMTP_SERVER,
        "client": SMTP_CLIENT,
        "notes": (
            "Lab plaintext SMTP submission on TCP/587 using a Docker bridge and "
            "dumpcap sidecar in the server netns."
        ),
    },
    "imap_standard_port": {
        "port": 143,
        "server": IMAP_SERVER,
        "client": IMAP_CLIENT,
        "notes": (
            "Lab plaintext IMAP CAPABILITY/LOGOUT on TCP/143 using a Docker bridge "
            "and dumpcap sidecar in the server netns."
        ),
    },
    "pop3_standard_port": {
        "port": 110,
        "server": POP3_SERVER,
        "client": POP3_CLIENT,
        "notes": (
            "Lab plaintext POP3 CAPA/QUIT on TCP/110 using a Docker bridge and "
            "dumpcap sidecar in the server netns."
        ),
    },
}


def _run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=check, capture_output=True, text=True)


def _docker_output(argv: list[str]) -> str:
    return _run(argv).stdout.strip()


def _cleanup(server_name: str, cap_name: str, net_name: str) -> None:
    _run(["docker", "rm", "-f", cap_name], check=False)
    _run(["docker", "rm", "-f", server_name], check=False)
    _run(["docker", "network", "rm", net_name], check=False)


def generate_case(case_id: str) -> Path:
    if shutil.which("docker") is None:
        raise RuntimeError("docker is required to generate lab mail protocol captures")
    spec = CASES[case_id]
    port = int(spec["port"])
    out_dir = ROOT / "tests" / "fixtures" / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    capture = out_dir / "capture.pcapng"
    server_name = f"securemail-step2-{case_id}-srv"
    cap_name = f"securemail-step2-{case_id}-cap"
    net_name = f"securemail-step2-{case_id}-net"
    _cleanup(server_name, cap_name, net_name)
    tmp = Path(tempfile.mkdtemp(prefix=f"securemail-lab-{case_id}-"))
    try:
        os.chmod(tmp, 0o1777)
        _run(["docker", "network", "create", net_name])
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                server_name,
                "--network",
                net_name,
                PYTHON_IMAGE,
                "python",
                "-c",
                str(spec["server"]),
            ]
        )
        time.sleep(1)
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                cap_name,
                "--network",
                f"container:{server_name}",
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
                f"tcp port {port}",
                "-q",
                "-w",
                "/data/out/capture.pcapng",
            ]
        )
        time.sleep(1)
        inspect = _run(["docker", "inspect", "-f", "{{.State.Running}}", cap_name])
        if inspect.stdout.strip() != "true":
            logs = _run(["docker", "logs", cap_name], check=False)
            raise RuntimeError(f"dumpcap sidecar failed:\n{logs.stdout}\n{logs.stderr}")
        server_ip = _docker_output(
            [
                "docker",
                "inspect",
                "-f",
                "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                server_name,
            ]
        )
        client = _run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                net_name,
                PYTHON_IMAGE,
                "python",
                "-c",
                str(spec["client"]),
                server_ip,
            ],
            check=False,
        )
        if client.returncode != 0:
            raise RuntimeError(f"{case_id} client failed:\n{client.stdout}\n{client.stderr}")
        time.sleep(1)
        _run(["docker", "stop", "-t", "2", cap_name], check=False)
        captured = tmp / "capture.pcapng"
        if not captured.is_file() or captured.stat().st_size < 64:
            logs = _run(["docker", "logs", cap_name], check=False)
            raise RuntimeError(f"lab capture missing or too small:\n{logs.stdout}\n{logs.stderr}")
        capture.write_bytes(captured.read_bytes())
    finally:
        _cleanup(server_name, cap_name, net_name)
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
            f"{GENERATOR} --case {case_id} --out tests/fixtures/{case_id}/capture.pcapng "
            f"(docker network {net_name}; dumpcap sidecar --network container:{server_name})"
        ),
        "notes": spec["notes"],
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
    parser.add_argument("--case", choices=["all", *sorted(CASES)], default="all")
    args = parser.parse_args()
    selected = list(CASES) if args.case == "all" else [args.case]
    for case_id in selected:
        capture = generate_case(case_id)
        print(f"wrote {capture} sha256={sha256_file(capture)}")


if __name__ == "__main__":
    main()
