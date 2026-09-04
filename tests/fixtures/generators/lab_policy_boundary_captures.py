"""Lab captures for Step 7 policy-boundary cases via OpenSSL 1.0.2u.

New generator (does not rewrite lab_legacy_openssl_captures.py or lab_cert_captures.py).
"""

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

GENERATOR = "tests/fixtures/generators/lab_policy_boundary_captures.py"
LEGACY_IMAGE = "securemail/legacy-openssl:1.0.2u"
PYTHON_IMAGE = (
    "python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3"
)
TSHARK_IMAGE = "securemail/tshark:step0"
DOCKERFILE = Path(__file__).with_name("legacy_openssl.Dockerfile")
PORT = 4433

CASES: dict[str, dict[str, object]] = {
    "tls10_negotiated": {
        "notes": "Lab TLS 1.0 negotiated exactly (OpenSSL 1.0.2u, AES128-SHA).",
        "tls_flag": "-tls1",
        "cipher": "AES128-SHA",
        "key_size": 2048,
        "verify_client": False,
    },
    "tls11_negotiated": {
        "notes": "Lab TLS 1.1 negotiated exactly (OpenSSL 1.0.2u, AES128-SHA).",
        "tls_flag": "-tls1_1",
        "cipher": "AES128-SHA",
        "key_size": 2048,
        "verify_client": False,
    },
    "tls12_null_cipher": {
        "notes": "Lab TLS 1.2 NULL cipher TLS_RSA_WITH_NULL_SHA via OpenSSL 1.0.2u.",
        "tls_flag": "-tls1_2",
        "cipher": "NULL-SHA",
        "key_size": 2048,
        "verify_client": False,
    },
    "tls12_export_cipher": {
        "notes": "Lab TLS 1.2 export cipher TLS_RSA_EXPORT_WITH_RC4_40_MD5 via OpenSSL 1.0.2u.",
        "tls_flag": "-tls1_2",
        "cipher": "EXP-RC4-MD5",
        "key_size": 2048,
        "verify_client": False,
    },
    "tls12_sha1_certificate_verify": {
        "notes": (
            "Lab TLS 1.2 mutual auth with SHA-1 handshake CertificateVerify "
            "(OpenSSL 1.0.2u -sigalgs RSA+SHA1)."
        ),
        "tls_flag": "-tls1_2",
        "cipher": "ECDHE-RSA-AES128-SHA",
        "key_size": 2048,
        "verify_client": True,
    },
    "cert_rsa1536": {
        "notes": (
            "Lab TLS 1.2 handshake with an RSA-1536 server certificate. Boundary below "
            "the RFC 9325 2048-bit RSA authentication-key requirement."
        ),
        "tls_flag": "-tls1_2",
        "cipher": "AES128-SHA",
        "key_size": 1536,
        "verify_client": False,
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


def _write_cert(directory: Path, *, key_size: int) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
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
        raise RuntimeError("docker is required to generate Step 7 lab captures")
    _ensure_legacy_image()
    spec = CASES[case_id]
    out_dir = ROOT / "tests" / "fixtures" / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    capture = out_dir / "capture.pcapng"
    server_name = f"securemail-step7-{case_id}-srv"
    cap_name = f"securemail-step7-{case_id}-cap"
    net_name = f"securemail-step7-{case_id}-net"
    _cleanup(server_name, cap_name, net_name)
    tmp = Path(tempfile.mkdtemp(prefix=f"securemail-step7-{case_id}-"))
    certs = tmp / "certs"
    certs.mkdir()
    _write_cert(certs, key_size=int(spec["key_size"]))
    tls_flag = str(spec["tls_flag"])
    cipher = str(spec["cipher"])
    verify_client = bool(spec["verify_client"])
    try:
        os.chmod(tmp, 0o1777)
        os.chmod(certs, 0o1777)
        _run(["docker", "network", "create", net_name])
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
            tls_flag,
            "-cipher",
            cipher,
        ]
        if verify_client:
            server_cmd.extend(["-Verify", "1", "-CAfile", "/certs/cert.pem"])
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
                "any",
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
        server_running = _run(["docker", "inspect", "-f", "{{.State.Running}}", server_name])
        if server_running.stdout.strip() != "true":
            logs = _run(["docker", "logs", server_name], check=False)
            raise RuntimeError(f"{case_id} server exited:\n{logs.stdout}\n{logs.stderr}")
        time.sleep(1)
        server_ip = _docker_output(
            [
                "docker",
                "inspect",
                "-f",
                "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                server_name,
            ]
        )
        client_script = (
            "printf 'GET / HTTP/1.0\\r\\n\\r\\n' | openssl s_client "
            f"-connect {server_ip}:{PORT} -ign_eof {tls_flag} -cipher {cipher}"
        )
        if verify_client:
            client_script += (
                " -cert /certs/cert.pem -key /certs/key.pem -sigalgs RSA+SHA1"
                " -CAfile /certs/cert.pem"
            )
        client_cmd = [
            "docker",
            "run",
            "--rm",
            "--network",
            net_name,
        ]
        if verify_client:
            client_cmd.extend(["--mount", f"type=bind,src={certs},dst=/certs,readonly=true"])
        client_cmd.extend([LEGACY_IMAGE, "sh", "-c", client_script])
        client = _run(client_cmd, check=False)
        if client.returncode != 0:
            raise RuntimeError(f"{case_id} client failed:\n{client.stdout}\n{client.stderr}")
        time.sleep(1)
        _run(["docker", "stop", "-t", "2", cap_name], check=False)
        captured = tmp / "capture.pcapng"
        if not captured.is_file() or captured.stat().st_size < 1024:
            size = captured.stat().st_size if captured.is_file() else 0
            logs = _run(["docker", "logs", cap_name], check=False)
            server_logs = _run(["docker", "logs", server_name], check=False)
            raise RuntimeError(
                f"lab capture missing or too small ({size} bytes):\n"
                f"dumpcap:\n{logs.stdout}\n{logs.stderr}\n"
                f"server:\n{server_logs.stdout}\n{server_logs.stderr}\n"
                f"client:\n{client.stdout}\n{client.stderr}"
            )
        capture.write_bytes(captured.read_bytes())
    finally:
        _cleanup(server_name, cap_name, net_name)
        shutil.rmtree(tmp, ignore_errors=True)

    dumpcap_version = _docker_output(
        ["docker", "run", "--rm", "--entrypoint", "dumpcap", TSHARK_IMAGE, "-v"]
    )
    openssl_version = _docker_output(["docker", "run", "--rm", LEGACY_IMAGE, "openssl", "version"])
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
            "legacy_image": LEGACY_IMAGE,
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
