"""Lab TLS 1.2 certificate-matrix captures (Step 5)."""

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

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tcp_common import ROOT, sha256_file  # noqa: E402

GENERATOR = "tests/fixtures/generators/lab_cert_captures.py"
PYTHON_IMAGE = (
    "python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3"
)
LEGACY_IMAGE = "securemail/legacy-openssl:1.0.2u"
TSHARK_IMAGE = "securemail/tshark:step0"
DOCKERFILE = Path(__file__).with_name("legacy_openssl.Dockerfile")
PORT = 4433

PYTHON_SERVER = r"""
import asyncio
import ssl
import sys

port = int(sys.argv[1])
ciphers = sys.argv[2]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
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
ciphers = sys.argv[3]
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
if ciphers:
    ctx.set_ciphers(ciphers)
raw = socket.create_connection((host, port), timeout=15)
sock = ctx.wrap_socket(raw, server_hostname="securemail.test")
sock.close()
"""

CASES: dict[str, dict[str, object]] = {
    "cert_valid_current": {
        "notes": (
            "Lab TLS 1.2 handshake with a currently valid RSA-2048 SHA-256 certificate "
            "(validity 2020-2099)."
        ),
        "engine": "python",
        "key_type": "rsa",
        "key_size": 2048,
        "hash_name": "sha256",
        "ciphers": "ECDHE-RSA-AES128-GCM-SHA256",
        "not_before": datetime(2020, 1, 1, tzinfo=UTC),
        "not_after": datetime(2099, 1, 1, tzinfo=UTC),
    },
    "cert_expired_rsa1024": {
        "notes": (
            "Lab TLS 1.2 handshake with an expired RSA-1024 certificate. Key size is a "
            "fact only; policy findings are Step 7."
        ),
        "engine": "legacy",
        "key_type": "rsa",
        "key_size": 1024,
        "hash_name": "sha256",
        "ciphers": "AES128-SHA",
        "not_before": datetime(2018, 1, 1, tzinfo=UTC),
        "not_after": datetime(2019, 1, 1, tzinfo=UTC),
    },
    "cert_not_yet_valid": {
        "notes": "Lab TLS 1.2 handshake with a not-yet-valid RSA-2048 certificate (2098-2099).",
        "engine": "python",
        "key_type": "rsa",
        "key_size": 2048,
        "hash_name": "sha256",
        "ciphers": "ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0",
        "not_before": datetime(2098, 1, 1, tzinfo=UTC),
        "not_after": datetime(2099, 1, 1, tzinfo=UTC),
    },
    "cert_ecdsa_p256": {
        "notes": "Lab TLS 1.2 handshake with an ECDSA P-256 SHA-256 certificate.",
        "engine": "python",
        "key_type": "ec",
        "key_size": 256,
        "hash_name": "sha256",
        "ciphers": "ECDHE-ECDSA-AES128-GCM-SHA256",
        "not_before": datetime(2020, 1, 1, tzinfo=UTC),
        "not_after": datetime(2099, 1, 1, tzinfo=UTC),
    },
    "cert_sha1_signed": {
        "notes": (
            "Lab TLS 1.2 handshake with a SHA-1-signed RSA-2048 certificate. Signature "
            "algorithm is a fact only; policy findings are Step 7."
        ),
        "engine": "legacy",
        "key_type": "rsa",
        "key_size": 2048,
        "hash_name": "sha1",
        "ciphers": "ECDHE-RSA-AES128-SHA",
        "not_before": datetime(2020, 1, 1, tzinfo=UTC),
        "not_after": datetime(2099, 1, 1, tzinfo=UTC),
    },
    "cert_expiry_warning": {
        "notes": (
            "Lab TLS 1.2 handshake with a certificate that expires 2026-09-18, inside a "
            "30-day warning window at analysis time 2026-09-04T12:00:00Z."
        ),
        "engine": "python",
        "key_type": "rsa",
        "key_size": 2048,
        "hash_name": "sha256",
        "ciphers": "ECDHE-RSA-AES128-GCM-SHA256",
        "not_before": datetime(2020, 1, 1, tzinfo=UTC),
        "not_after": datetime(2026, 9, 18, tzinfo=UTC),
        "analyze": {
            "analysis_time": "2026-09-04T12:00:00Z",
            "expiry_warning_days": 30,
        },
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


def _ensure_legacy_image() -> None:
    inspect = _run(["docker", "image", "inspect", LEGACY_IMAGE], check=False)
    if inspect.returncode == 0:
        return
    build = _run(
        [
            "docker",
            "build",
            "-f",
            str(DOCKERFILE),
            "-t",
            LEGACY_IMAGE,
            str(DOCKERFILE.parent),
        ]
    )
    if build.returncode != 0:
        raise RuntimeError(f"legacy OpenSSL image build failed:\n{build.stdout}\n{build.stderr}")


def _write_key(directory: Path, *, key_type: str, key_size: int) -> None:
    if key_type == "ec":
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    (directory / "key.pem").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_cert_cryptography(
    directory: Path,
    *,
    not_before: datetime,
    not_after: datetime,
) -> None:
    key = serialization.load_pem_private_key((directory / "key.pem").read_bytes(), password=None)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "securemail.test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("securemail.test")]), False)
        .sign(key, hashes.SHA256())
    )
    (directory / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_cert_sha1(
    directory: Path,
    *,
    not_before: datetime,
    not_after: datetime,
) -> None:
    start = not_before.strftime("%Y%m%d%H%M%SZ")
    end = not_after.strftime("%Y%m%d%H%M%SZ")
    csr = _run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            "0",
            "--mount",
            f"type=bind,src={directory},dst=/certs",
            PYTHON_IMAGE,
            "openssl",
            "req",
            "-new",
            "-key",
            "/certs/key.pem",
            "-subj",
            "/CN=securemail.test",
            "-out",
            "/certs/csr.pem",
        ],
        check=False,
    )
    if csr.returncode != 0:
        raise RuntimeError(f"SHA-1 CSR failed:\n{csr.stdout}\n{csr.stderr}")
    signed = _run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            "0",
            "--mount",
            f"type=bind,src={directory},dst=/certs",
            PYTHON_IMAGE,
            "openssl",
            "x509",
            "-req",
            "-in",
            "/certs/csr.pem",
            "-signkey",
            "/certs/key.pem",
            "-sha1",
            "-not_before",
            start,
            "-not_after",
            end,
            "-out",
            "/certs/cert.pem",
        ],
        check=False,
    )
    if signed.returncode != 0:
        raise RuntimeError(f"SHA-1 certificate sign failed:\n{signed.stdout}\n{signed.stderr}")


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
        raise RuntimeError("docker is required to generate lab certificate captures")
    spec = CASES[case_id]
    if spec["engine"] == "legacy":
        _ensure_legacy_image()
    out_dir = ROOT / "tests" / "fixtures" / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    capture = out_dir / "capture.pcapng"
    server_name = f"securemail-step5-{case_id}-srv"
    cap_name = f"securemail-step5-{case_id}-cap"
    net_name = f"securemail-step5-{case_id}-net"
    _cleanup(server_name, cap_name, net_name)
    tmp = Path(tempfile.mkdtemp(prefix=f"securemail-cert-{case_id}-"))
    certs = tmp / "certs"
    certs.mkdir()
    _write_key(certs, key_type=str(spec["key_type"]), key_size=int(spec["key_size"]))
    not_before = spec["not_before"]
    not_after = spec["not_after"]
    assert isinstance(not_before, datetime)
    assert isinstance(not_after, datetime)
    if spec["hash_name"] == "sha1":
        _write_cert_sha1(certs, not_before=not_before, not_after=not_after)
    else:
        _write_cert_cryptography(certs, not_before=not_before, not_after=not_after)
    try:
        os.chmod(tmp, 0o1777)
        os.chmod(certs, 0o1777)
        _run(["docker", "network", "create", net_name])
        ciphers = str(spec["ciphers"])
        if spec["engine"] == "python":
            _run(
                [
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
                    ciphers,
                ]
            )
        else:
            _run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    server_name,
                    "--network",
                    net_name,
                    "--mount",
                    f"type=bind,src={certs},dst=/certs,readonly=true",
                    LEGACY_IMAGE,
                    "openssl",
                    "s_server",
                    "-accept",
                    str(PORT),
                    "-cert",
                    "/certs/cert.pem",
                    "-key",
                    "/certs/key.pem",
                    "-www",
                    "-tls1_2",
                    "-cipher",
                    ciphers,
                ]
            )
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
                    ciphers,
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
                    LEGACY_IMAGE,
                    "sh",
                    "-c",
                    (
                        "printf 'GET / HTTP/1.0\\r\\n\\r\\n' | openssl s_client "
                        f"-connect {server_ip}:{PORT} -ign_eof -tls1_2 -cipher {ciphers}"
                    ),
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
    openssl_version = _docker_output(
        [
            "docker",
            "run",
            "--rm",
            LEGACY_IMAGE if spec["engine"] == "legacy" else PYTHON_IMAGE,
            "openssl",
            "version",
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
            "openssl": openssl_version,
            "python_image": PYTHON_IMAGE,
            "tshark_image": TSHARK_IMAGE,
        },
    }
    if spec["engine"] == "legacy":
        payload["tool_versions"]["legacy_image"] = LEGACY_IMAGE
    (out_dir / "provenance.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    analyze = spec.get("analyze")
    if isinstance(analyze, dict):
        (out_dir / "analyze.json").write_text(
            json.dumps(analyze, indent=2, sort_keys=True) + "\n", encoding="utf-8"
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
