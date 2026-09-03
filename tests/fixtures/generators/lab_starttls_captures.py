"""Lab-capture STARTTLS success, implicit TLS with ALPN, and port-only TLS."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tcp_common import ROOT, sha256_file  # noqa: E402

GENERATOR = "tests/fixtures/generators/lab_starttls_captures.py"
PYTHON_IMAGE = (
    "python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3"
)
TSHARK_IMAGE = "securemail/tshark:step0"

SMTP_STARTTLS_SERVER = r"""
import asyncio
import ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/certs/cert.pem", "/certs/key.pem")

async def handle(reader, writer):
    writer.write(b"220 securemail.test ESMTP\r\n")
    await writer.drain()
    tls = False
    while True:
        line = await reader.readline()
        if not line:
            break
        command = line.decode("ascii", "replace").strip().split(" ", 1)[0].upper()
        if command == "EHLO":
            if tls:
                writer.write(b"250-securemail.test Hello\r\n250 OK\r\n")
            else:
                writer.write(b"250-securemail.test Hello\r\n250-STARTTLS\r\n250 OK\r\n")
        elif command == "STARTTLS" and not tls:
            writer.write(b"220 Ready to start TLS\r\n")
            await writer.drain()
            await writer.start_tls(ctx)
            tls = True
            continue
        elif command == "QUIT":
            writer.write(b"221 Bye\r\n")
            await writer.drain()
            break
        else:
            writer.write(b"250 OK\r\n")
        await writer.drain()
    writer.close()
    await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", 587)
    async with server:
        await server.serve_forever()

asyncio.run(main())
"""

SMTP_STARTTLS_CLIENT = r"""
import smtplib
import ssl
import sys

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
client = smtplib.SMTP(sys.argv[1], 587, timeout=15)
client.ehlo()
client.starttls(context=ctx)
client.ehlo()
client.quit()
"""

IMAP_STARTTLS_SERVER = r"""
import asyncio
import ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/certs/cert.pem", "/certs/key.pem")

async def handle(reader, writer):
    writer.write(b"* OK IMAP4rev1 ready\r\n")
    await writer.drain()
    tls = False
    while True:
        line = await reader.readline()
        if not line:
            break
        decoded = line.decode("ascii", "replace").strip()
        parts = decoded.split()
        tag = parts[0] if parts else "*"
        command = parts[1].upper() if len(parts) >= 2 else ""
        if command == "CAPABILITY":
            if tls:
                caps = b"* CAPABILITY IMAP4rev1\r\n"
            else:
                caps = b"* CAPABILITY IMAP4rev1 STARTTLS\r\n"
            writer.write(caps + f"{tag} OK CAPABILITY completed\r\n".encode("ascii"))
        elif command == "STARTTLS" and not tls:
            writer.write(f"{tag} OK begin TLS\r\n".encode("ascii"))
            await writer.drain()
            await writer.start_tls(ctx)
            tls = True
            continue
        elif command == "LOGOUT":
            writer.write(b"* BYE logging out\r\n")
            writer.write(f"{tag} OK LOGOUT completed\r\n".encode("ascii"))
            await writer.drain()
            break
        else:
            writer.write(f"{tag} OK\r\n".encode("ascii"))
        await writer.drain()
    writer.close()
    await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", 143)
    async with server:
        await server.serve_forever()

asyncio.run(main())
"""

IMAP_STARTTLS_CLIENT = r"""
import imaplib
import ssl
import sys

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
client = imaplib.IMAP4(sys.argv[1], 143)
client.starttls(ssl_context=ctx)
client.logout()
"""

POP3_STLS_SERVER = r"""
import asyncio
import ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/certs/cert.pem", "/certs/key.pem")

async def handle(reader, writer):
    writer.write(b"+OK POP3 ready\r\n")
    await writer.drain()
    tls = False
    while True:
        line = await reader.readline()
        if not line:
            break
        command = line.decode("ascii", "replace").strip().split(" ", 1)[0].upper()
        if command == "CAPA":
            if tls:
                writer.write(b"+OK Capability list follows\r\nUSER\r\n.\r\n")
            else:
                writer.write(b"+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n")
        elif command == "STLS" and not tls:
            writer.write(b"+OK Begin TLS\r\n")
            await writer.drain()
            await writer.start_tls(ctx)
            tls = True
            continue
        elif command == "QUIT":
            writer.write(b"+OK Bye\r\n")
            await writer.drain()
            break
        else:
            writer.write(b"+OK\r\n")
        await writer.drain()
    writer.close()
    await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", 110)
    async with server:
        await server.serve_forever()

asyncio.run(main())
"""

POP3_STLS_CLIENT = r"""
import poplib
import ssl
import sys

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
client = poplib.POP3(sys.argv[1], 110, timeout=15)
client.stls(context=ctx)
client.quit()
"""

IMPLICIT_SERVER = r"""
import asyncio
import ssl
import sys

alpn = sys.argv[1]
port = int(sys.argv[2])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain("/certs/cert.pem", "/certs/key.pem")
if alpn:
    ctx.set_alpn_protocols([alpn])

async def handle(reader, writer):
    await asyncio.sleep(0.3)
    writer.close()
    await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", port, ssl=ctx)
    async with server:
        await server.serve_forever()

asyncio.run(main())
"""

IMPLICIT_CLIENT = r"""
import socket
import ssl
import sys

alpn = sys.argv[1]
host = sys.argv[2]
port = int(sys.argv[3])
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
if alpn:
    ctx.set_alpn_protocols([alpn])
raw = socket.create_connection((host, port), timeout=15)
sock = ctx.wrap_socket(raw, server_hostname="securemail.test")
sock.close()
"""

CASES: dict[str, dict[str, str | int]] = {
    "smtp_starttls_success": {
        "port": 587,
        "mode": "starttls",
        "server": SMTP_STARTTLS_SERVER,
        "client": SMTP_STARTTLS_CLIENT,
        "notes": "Lab SMTP STARTTLS upgrade on TCP/587 with a real TLS ClientHello.",
    },
    "imap_starttls_success": {
        "port": 143,
        "mode": "starttls",
        "server": IMAP_STARTTLS_SERVER,
        "client": IMAP_STARTTLS_CLIENT,
        "notes": "Lab IMAP STARTTLS upgrade on TCP/143 with a real TLS ClientHello.",
    },
    "pop3_stls_success": {
        "port": 110,
        "mode": "starttls",
        "server": POP3_STLS_SERVER,
        "client": POP3_STLS_CLIENT,
        "notes": "Lab POP3 STLS upgrade on TCP/110 with a real TLS ClientHello.",
    },
    "smtp_implicit_tls": {
        "port": 465,
        "mode": "implicit",
        "alpn": "smtp",
        "notes": "Lab implicit TLS on TCP/465 with negotiated ALPN smtp.",
    },
    "imap_implicit_tls": {
        "port": 993,
        "mode": "implicit",
        "alpn": "imap",
        "notes": "Lab implicit TLS on TCP/993 with negotiated ALPN imap.",
    },
    "pop3_implicit_tls": {
        "port": 995,
        "mode": "implicit",
        "alpn": "pop3",
        "notes": "Lab implicit TLS on TCP/995 with negotiated ALPN pop3.",
    },
    "tls_mail_port_no_alpn": {
        "port": 993,
        "mode": "implicit",
        "alpn": "",
        "notes": (
            "Lab TLS on TCP/993 without ALPN. Port-only mail identity must stay indeterminate."
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


def _write_cert(directory: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "securemail.test")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("securemail.test")]), False)
        .sign(key, hashes.SHA256())
    )
    (directory / "key.pem").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (directory / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def generate_case(case_id: str) -> Path:
    if shutil.which("docker") is None:
        raise RuntimeError("docker is required to generate lab STARTTLS captures")
    spec = CASES[case_id]
    port = int(spec["port"])
    out_dir = ROOT / "tests" / "fixtures" / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    capture = out_dir / "capture.pcapng"
    server_name = f"securemail-step3-{case_id}-srv"
    cap_name = f"securemail-step3-{case_id}-cap"
    net_name = f"securemail-step3-{case_id}-net"
    _cleanup(server_name, cap_name, net_name)
    tmp = Path(tempfile.mkdtemp(prefix=f"securemail-lab-{case_id}-"))
    certs = tmp / "certs"
    certs.mkdir()
    _write_cert(certs)
    try:
        os.chmod(tmp, 0o1777)
        os.chmod(certs, 0o1777)
        _run(["docker", "network", "create", net_name])
        if spec["mode"] == "starttls":
            server_cmd = [
                "docker",
                "run",
                "-d",
                "--name",
                server_name,
                "--network",
                net_name,
                "--mount",
                f"type=bind,src={certs},dst=/certs,readonly=true",
                PYTHON_IMAGE,
                "python",
                "-c",
                str(spec["server"]),
            ]
        else:
            server_cmd = [
                "docker",
                "run",
                "-d",
                "--name",
                server_name,
                "--network",
                net_name,
                "--mount",
                f"type=bind,src={certs},dst=/certs,readonly=true",
                PYTHON_IMAGE,
                "python",
                "-c",
                IMPLICIT_SERVER,
                str(spec.get("alpn", "")),
                str(port),
            ]
        _run(server_cmd)
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
        if spec["mode"] == "starttls":
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
        else:
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
                    IMPLICIT_CLIENT,
                    str(spec.get("alpn", "")),
                    server_ip,
                    str(port),
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
