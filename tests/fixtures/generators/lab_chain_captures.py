"""Lab TLS 1.2 certificate-chain captures (Step 6)."""

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
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tcp_common import ROOT, sha256_file  # noqa: E402

GENERATOR = "tests/fixtures/generators/lab_chain_captures.py"
PYTHON_IMAGE = (
    "python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3"
)
TSHARK_IMAGE = "securemail/tshark:step0"
PORT = 4433
NOT_BEFORE = datetime(2020, 1, 1, tzinfo=UTC)
NOT_AFTER = datetime(2099, 1, 1, tzinfo=UTC)

# Throwaway lab CA private key. Public certificate is pinned in
# src/securemail/adapters/pki/trust-store-snapshot.pem. Not a production secret.
_LAB_ROOT_KEY_PEM = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsCcLpyfIkODAFf/ntbX66F8MFkIFgP8fSU9F6piizyEOUN37
UzdNDD4NpPZ7PiFoRBw/v1nE8SDh0Vs1WL3hI+LM45rIpyxh1TgSQtQWIqfNt+wR
SIhmrjjIF6g8XeWo3Lc5MsNFJOiBgsaw/D8X0AGUFVQCGJaHK7SBgguY2DUSlGTG
6jE6qk0oYGquLgGeOQAXo6BrU1U+6cuSOT9dI+mKZM/yYmpC9SSKF1s0ARpWG0wc
rWBFQwd0U7MHH4ZL10hi1s+oJ3r3YjeT4kCk6ZFEADoEP5BXM8SRI7qW8PvtladX
OvOJB4ilURwbR7JLtYFGldapJKnCEeZH1Kl20QIDAQABAoH/afM+u5Pp3MrikabP
CvFZV5dODG46JAkMdOSuT+FHFuoedP/BczAukT8w6p4IP+GgdnhxAKxnlkfof/5A
Sg9PbBQlM3MM2Pqm0lsOXfc93rCU+uQTEeDiqgkY7JwzWe239tzvpi75sBJrkKbb
PFerevDyimcY26YHb6vwOXoC/9qyUUtEID1g6IcCZcRVTiGUn3sEZbWxko4dQLW1
CXigIf74Lg29aTURFlW0zyZriUn5RQwhY5cMFA23reBXL7LpIVU+0EG5i+IWUVKH
uh6aDzVAa+CP9EIlLzC5Zf771uWTZb7vPF/XvHsnNloeZlt3eknOfOjWGXYHh1nd
SIYTAoGBAPXZL62dKKwq3BFTZaqf3nfvHCVicpzKwmGlzExOPSBqhh6oxGl8hcL6
JXWlUmiyQQkgKvxQfzzJIJG4K9I5LeXJ+gavs2rYQ1Ig/xmXb+xO0pLVyEVC1zkq
/fYfYGp3cfTQ7Gv6136Tbaui9Qpzclb8h7cz/gt+RqnjiUGjLg1rAoGBALdtHkxS
u/ZhF/Q5vSO/PgyQ6wOgJYX+0TB/KppMg8rPRQkPrWhR3ew+o4xF0UJOSNItqIDA
zxqXziQ3p2nH9LMtCDJYTBntc77xmoiFzfg+ZAjZoamU90MtDCbjD1ZGxrAsnLrZ
dMkanpMcTrTJxadKK6a9uTXw7N+rsFSd6n+zAoGBAO4sWY9luNiKsSar18ukE7+3
S1pAdO7HU+eL2091YKy95m9fauES/Pd2pcHCxwKc5nqzylEknw/BficN+I4yTO/Y
a7v8jeIN37J6OwmM96ZEeqY8LEhFSAKfTugZX6vlSeY2XUUC/7AlndLxDVnxnCz/
e2+WFCEIVecSg4+uSdg/AoGBAITJhemS62fNml2/fuFmDTFjp/8T7JY4hpApP1o8
khw8OKn6o3ql6ZahMhzWXks2CRm+3AF5k3SY+S7W62d0zfz4WLq5mT4b3HMazNiQ
pS9VW23cv1/Y67fB4M42CmBXFHdtlHjf+9+qWan+ECxo9aHJ3Bf1uSMHqzOxQxG+
0IhpAoGBAOI1SamiKXKCssNWVZl+6dP28t/WNh3mRLLNbDnnLZ20XuqpTzHpiFcs
Ov3m549SBPV40r8mjMpsSnzG/sToTbW/ZibxBTwMHMg8T9N/ye6jD2fAkDxvCt7b
MEohB3FmZPN7MbP52BSbp5kOh3ckpR9AzeQ4xLMrJLZG1+2d6kun
-----END RSA PRIVATE KEY-----
"""

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
server_hostname = sys.argv[4]
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
if ciphers:
    ctx.set_ciphers(ciphers)
raw = socket.create_connection((host, port), timeout=15)
sock = ctx.wrap_socket(raw, server_hostname=server_hostname)
sock.close()
"""

CASES: dict[str, dict[str, object]] = {
    "cert_chain_lab_trusted": {
        "notes": (
            "Lab TLS 1.2 handshake with a throwaway-CA chain (leaf + intermediate). "
            "The lab root is in the pinned trust snapshot."
        ),
        "send_chain": True,
        "self_signed": False,
        "server_hostname": "securemail.test",
        "san": "securemail.test",
    },
    "cert_chain_self_signed": {
        "notes": (
            "Lab TLS 1.2 handshake with a self-signed leaf. The signer is not in "
            "the pinned trust snapshot."
        ),
        "send_chain": False,
        "self_signed": True,
        "server_hostname": "securemail.test",
        "san": "securemail.test",
    },
    "cert_chain_missing_intermediate": {
        "notes": (
            "Lab TLS 1.2 handshake that sends only the leaf. The issuing "
            "intermediate is omitted from the wire."
        ),
        "send_chain": False,
        "self_signed": False,
        "server_hostname": "securemail.test",
        "san": "securemail.test",
    },
    "cert_chain_san_match": {
        "notes": ("Lab TLS 1.2 trusted chain whose SAN matches the client SNI securemail.test."),
        "send_chain": True,
        "self_signed": False,
        "server_hostname": "securemail.test",
        "san": "securemail.test",
    },
    "cert_chain_san_mismatch": {
        "notes": (
            "Lab TLS 1.2 trusted chain with SAN securemail.test and client SNI "
            "wrong.example.test. Path validity and identity are independent."
        ),
        "send_chain": True,
        "self_signed": False,
        "server_hostname": "wrong.example.test",
        "san": "securemail.test",
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


def _name(*parts: tuple[str, str]) -> x509.Name:
    oid = {"O": NameOID.ORGANIZATION_NAME, "CN": NameOID.COMMON_NAME}
    return x509.Name([x509.NameAttribute(oid[key], value) for key, value in parts])


def _ca_extensions(public_key: object, *, path_length: int | None) -> list[x509.ExtensionType]:
    return [
        x509.BasicConstraints(ca=True, path_length=path_length),
        x509.KeyUsage(False, False, False, False, False, True, True, False, False),
        x509.SubjectKeyIdentifier.from_public_key(public_key),  # type: ignore[arg-type]
    ]


def _leaf_extensions(san: str, public_key: object) -> list[x509.ExtensionType]:
    return [
        x509.BasicConstraints(ca=False, path_length=None),
        x509.KeyUsage(True, False, False, False, True, False, False, False, False),
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        x509.SubjectAlternativeName([x509.DNSName(san)]),
        x509.SubjectKeyIdentifier.from_public_key(public_key),  # type: ignore[arg-type]
    ]


def _lab_root() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = serialization.load_pem_private_key(_LAB_ROOT_KEY_PEM, password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    anchors = x509.load_pem_x509_certificates(
        (ROOT / "src/securemail/adapters/pki/trust-store-snapshot.pem").read_bytes()
    )
    for certificate in anchors:
        names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if names and names[0].value == "SecureMail Lab Root CA":
            return key, certificate
    raise RuntimeError("SecureMail Lab Root CA is missing from the pinned trust snapshot")


def _sign(
    *,
    subject: x509.Name,
    issuer: x509.Name,
    public_key: object,
    issuer_key: rsa.RSAPrivateKey,
    serial: int,
    extensions: list[x509.ExtensionType],
    aki: x509.Certificate | None = None,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)  # type: ignore[arg-type]
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
    )
    for extension in extensions:
        critical = isinstance(extension, (x509.BasicConstraints, x509.KeyUsage))
        builder = builder.add_extension(extension, critical)
    if aki is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(aki.public_key()),
            False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _write_material(directory: Path, spec: dict[str, object]) -> None:
    root_key, root_cert = _lab_root()
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (directory / "key.pem").write_bytes(
        leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    san = str(spec["san"])
    leaf_name = _name(("CN", san))
    if spec["self_signed"]:
        leaf = _sign(
            subject=leaf_name,
            issuer=leaf_name,
            public_key=leaf_key.public_key(),
            issuer_key=leaf_key,
            serial=x509.random_serial_number(),
            extensions=_leaf_extensions(san, leaf_key.public_key()),
        )
        (directory / "cert.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        return
    int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    intermediate = _sign(
        subject=_name(("O", "SecureMail Lab"), ("CN", "SecureMail Lab Intermediate CA")),
        issuer=root_cert.subject,
        public_key=int_key.public_key(),
        issuer_key=root_key,
        serial=x509.random_serial_number(),
        extensions=_ca_extensions(int_key.public_key(), path_length=0),
        aki=root_cert,
    )
    leaf = _sign(
        subject=leaf_name,
        issuer=intermediate.subject,
        public_key=leaf_key.public_key(),
        issuer_key=int_key,
        serial=x509.random_serial_number(),
        extensions=_leaf_extensions(san, leaf_key.public_key()),
        aki=intermediate,
    )
    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM)
    if spec["send_chain"]:
        chain_pem = leaf_pem + intermediate.public_bytes(serialization.Encoding.PEM)
        (directory / "cert.pem").write_bytes(chain_pem)
    else:
        (directory / "cert.pem").write_bytes(leaf_pem)


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
        raise RuntimeError("docker is required to generate lab chain captures")
    spec = CASES[case_id]
    out_dir = ROOT / "tests" / "fixtures" / case_id
    out_dir.mkdir(parents=True, exist_ok=True)
    capture = out_dir / "capture.pcapng"
    server_name = f"securemail-step6-{case_id}-srv"
    cap_name = f"securemail-step6-{case_id}-cap"
    net_name = f"securemail-step6-{case_id}-net"
    _cleanup(server_name, cap_name, net_name)
    tmp = Path(tempfile.mkdtemp(prefix=f"securemail-chain-{case_id}-"))
    certs = tmp / "certs"
    certs.mkdir()
    _write_material(certs, spec)
    try:
        os.chmod(tmp, 0o1777)
        os.chmod(certs, 0o1777)
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
                "--mount",
                f"type=bind,src={certs},dst=/certs,readonly=true",
                PYTHON_IMAGE,
                "python",
                "-c",
                PYTHON_SERVER,
                str(PORT),
                "ECDHE-RSA-AES128-GCM-SHA256",
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
                "ECDHE-RSA-AES128-GCM-SHA256",
                str(spec["server_hostname"]),
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
    openssl_version = _docker_output(["docker", "run", "--rm", PYTHON_IMAGE, "openssl", "version"])
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
