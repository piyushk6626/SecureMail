"""Lab TLS 1.2 ECDHE, TLS 1.3 full, HelloRetryRequest, and PSK-only resumption captures."""

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

GENERATOR = "tests/fixtures/generators/lab_tls_handshake_captures.py"
PYTHON_IMAGE = (
    "python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3"
)
TSHARK_IMAGE = "securemail/tshark:step0"
PORT = 4433

PYTHON_SERVER = r"""
import asyncio
import ssl
import sys

port = int(sys.argv[1])
min_version = getattr(ssl.TLSVersion, sys.argv[2])
max_version = getattr(ssl.TLSVersion, sys.argv[3])
ciphers = sys.argv[4] if len(sys.argv) > 4 else ""
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = min_version
ctx.maximum_version = max_version
ctx.load_cert_chain("/certs/cert.pem", "/certs/key.pem")
if ciphers:
    ctx.set_ciphers(ciphers)

async def handle(reader, writer):
    await asyncio.sleep(0.5)
    writer.close()
    await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", port, ssl=ctx)
    async with server:
        await server.serve_forever()

asyncio.run(main())
"""

PYTHON_CLIENT = r"""
import socket
import ssl
import sys

host = sys.argv[1]
port = int(sys.argv[2])
min_version = getattr(ssl.TLSVersion, sys.argv[3])
max_version = getattr(ssl.TLSVersion, sys.argv[4])
ciphers = sys.argv[5] if len(sys.argv) > 5 else ""
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = min_version
ctx.maximum_version = max_version
if ciphers:
    ctx.set_ciphers(ciphers)
raw = socket.create_connection((host, port), timeout=15)
sock = ctx.wrap_socket(raw, server_hostname="securemail.test")
sock.close()
"""

OPENSSL_CLIENT = r"""
import subprocess
import sys
import time

host = sys.argv[1]
extra = sys.argv[2:]
proc = subprocess.Popen(
    ["openssl", "s_client", "-connect", f"{host}:4433", "-ign_eof", *extra],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)
time.sleep(2.5)
proc.kill()
try:
    proc.communicate(timeout=5)
except subprocess.TimeoutExpired:
    proc.kill()
    proc.wait(timeout=5)
"""

PSK_CLIENT = r"""
import subprocess
import sys
import time

host = sys.argv[1]


def run_client(args):
    proc = subprocess.Popen(
        ["openssl", "s_client", "-connect", f"{host}:4433", "-ign_eof", *args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    time.sleep(2.5)
    proc.kill()
    try:
        proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


run_client(["-tls1_3", "-sess_out", "/data/sess.pem"])
time.sleep(0.5)
run_client(
    [
        "-tls1_3",
        "-sess_in",
        "/data/sess.pem",
        "-allow_no_dhe_kex",
        "-prefer_no_dhe_kex",
    ]
)
"""

CASES: dict[str, dict[str, str]] = {
    "tls12_ecdhe": {
        "notes": "Lab TLS 1.2 ECDHE-RSA-AES128-GCM-SHA256 handshake on TCP/4433.",
        "engine": "python",
        "min_version": "TLSv1_2",
        "max_version": "TLSv1_2",
        "ciphers": "ECDHE-RSA-AES128-GCM-SHA256",
    },
    "tls13_full_handshake": {
        "notes": "Lab TLS 1.3 full handshake (not a resumption) on TCP/4433.",
        "engine": "python",
        "min_version": "TLSv1_3",
        "max_version": "TLSv1_3",
        "ciphers": "",
    },
    "tls13_hello_retry_request": {
        "notes": (
            "Lab TLS 1.3 HelloRetryRequest: server offers only P-256, client first "
            "key_share is X25519."
        ),
        "engine": "openssl",
        "server_args": "-tls1_3 -groups P-256",
        "client_args": "-tls1_3 -groups X25519:P-256",
    },
    "tls13_psk_only_resumption": {
        "notes": (
            "Lab TLS 1.3 PSK-only resumption: first full handshake, then a second "
            "connection using -prefer_no_dhe_kex so the server selects psk_ke."
        ),
        "engine": "openssl_psk",
        "server_args": "-tls1_3 -allow_no_dhe_kex -prefer_no_dhe_kex",
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


def _split_args(raw: str) -> list[str]:
    return [part for part in raw.split(" ") if part]


def _start_dumpcap(cap_name: str, server_name: str, tmp: Path) -> None:
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
            f"tcp port {PORT}",
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


def generate_case(case_id: str) -> Path:
    if shutil.which("docker") is None:
        raise RuntimeError("docker is required to generate lab TLS captures")
    spec = CASES[case_id]
    out_dir = ROOT / "tests" / "fixtures" / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    capture = out_dir / "capture.pcapng"
    server_name = f"securemail-step4-{case_id}-srv"
    cap_name = f"securemail-step4-{case_id}-cap"
    net_name = f"securemail-step4-{case_id}-net"
    _cleanup(server_name, cap_name, net_name)
    tmp = Path(tempfile.mkdtemp(prefix=f"securemail-lab-{case_id}-"))
    certs = tmp / "certs"
    certs.mkdir()
    _write_cert(certs)
    try:
        os.chmod(tmp, 0o1777)
        os.chmod(certs, 0o1777)
        _run(["docker", "network", "create", net_name])
        if spec["engine"] == "python":
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
                PYTHON_SERVER,
                str(PORT),
                spec["min_version"],
                spec["max_version"],
                spec.get("ciphers", ""),
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
                "openssl",
                "s_server",
                "-accept",
                str(PORT),
                "-cert",
                "/certs/cert.pem",
                "-key",
                "/certs/key.pem",
                "-www",
                *_split_args(spec["server_args"]),
            ]
        _run(server_cmd)
        time.sleep(1)
        _start_dumpcap(cap_name, server_name, tmp)
        server_ip = _docker_output(
            [
                "docker",
                "inspect",
                "-f",
                "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                server_name,
            ]
        )
        if spec["engine"] == "python":
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
                    PYTHON_CLIENT,
                    server_ip,
                    str(PORT),
                    spec["min_version"],
                    spec["max_version"],
                    spec.get("ciphers", ""),
                ],
                check=False,
            )
        elif spec["engine"] == "openssl_psk":
            client = _run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    net_name,
                    "--mount",
                    f"type=bind,src={tmp},dst=/data",
                    PYTHON_IMAGE,
                    "python",
                    "-c",
                    PSK_CLIENT,
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
                    OPENSSL_CLIENT,
                    server_ip,
                    *_split_args(spec["client_args"]),
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
    openssl_version = (
        _run(
            ["docker", "run", "--rm", PYTHON_IMAGE, "openssl", "version"],
            check=False,
        ).stdout.strip()
        or "unknown"
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
            "openssl": openssl_version,
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
