"""Bounded `openssl verify` subprocess used only from the Step 6 differential test."""

from __future__ import annotations

import platform
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from securemail.adapters.analyzers.sandbox import assert_fixed_argv
from securemail.domain.evidence.certificate import MAX_CERTIFICATE_DER_BYTES, MAX_CHAIN_DEPTH

_OPENSSL_TIMEOUT_SECONDS = 15
_MAX_OUTPUT_BYTES = 65_536
_DARWIN_OPENSSL = Path("/opt/homebrew/bin/openssl")


class OpenSslCrosscheckError(RuntimeError):
    """Raised when the OpenSSL binary cannot be invoked safely."""


@dataclass(frozen=True)
class OpenSslVerifyResult:
    exit_code: int
    stdout: str
    stderr: str
    path_valid: bool


def resolve_openssl_binary() -> Path:
    """Homebrew OpenSSL on macOS; never `/usr/bin/openssl` (LibreSSL)."""

    if platform.system() == "Darwin":
        return _DARWIN_OPENSSL
    found = shutil.which("openssl")
    return Path(found) if found else Path("/usr/bin/openssl")


def openssl_available(binary: Path | None = None) -> bool:
    path = binary if binary is not None else resolve_openssl_binary()
    if not path.is_file():
        return False
    completed = subprocess.run(
        [str(path), "version"],
        check=False,
        capture_output=True,
        timeout=_OPENSSL_TIMEOUT_SECONDS,
    )
    text = completed.stdout.decode("utf-8", errors="replace")
    return completed.returncode == 0 and text.startswith("OpenSSL") and "LibreSSL" not in text


def openssl_verify_chain(
    *,
    leaf_der: bytes,
    intermediate_ders: Sequence[bytes],
    trust_pem_path: Path,
    verification_time: datetime,
    openssl_binary: Path | None = None,
) -> OpenSslVerifyResult:
    """Path-only `openssl verify` at an explicit instant. Never used in production."""

    _bound_der(leaf_der)
    if len(intermediate_ders) + 1 > MAX_CHAIN_DEPTH:
        raise OpenSslCrosscheckError("chain exceeds the configured depth bound")
    for payload in intermediate_ders:
        _bound_der(payload)
    binary = openssl_binary if openssl_binary is not None else resolve_openssl_binary()
    if not openssl_available(binary):
        raise OpenSslCrosscheckError(f"OpenSSL binary is missing or is LibreSSL: {binary}")
    if verification_time.tzinfo is None:
        instant = verification_time.replace(tzinfo=UTC)
    else:
        instant = verification_time
    epoch = str(int(instant.timestamp()))
    with tempfile.TemporaryDirectory(prefix="securemail-openssl-") as tmp:
        tmp_dir = Path(tmp)
        leaf_path = tmp_dir / "leaf.pem"
        leaf_path.write_bytes(_der_to_pem(leaf_der))
        argv = [
            str(binary),
            "verify",
            "-CAfile",
            str(trust_pem_path),
            "-attime",
            epoch,
        ]
        if intermediate_ders:
            untrusted = tmp_dir / "untrusted.pem"
            untrusted.write_bytes(b"".join(_der_to_pem(item) for item in intermediate_ders))
            argv.extend(["-untrusted", str(untrusted)])
        argv.append(str(leaf_path))
        assert_fixed_argv(argv)
        try:
            completed = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                timeout=_OPENSSL_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise OpenSslCrosscheckError(
                f"openssl verify exceeded {_OPENSSL_TIMEOUT_SECONDS}s timeout"
            ) from exc
        stdout = _bound_text(completed.stdout)
        stderr = _bound_text(completed.stderr)
        return OpenSslVerifyResult(
            exit_code=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            path_valid=completed.returncode == 0,
        )


def _bound_der(payload: bytes) -> None:
    if not payload:
        raise OpenSslCrosscheckError("refusing empty certificate bytes")
    if len(payload) > MAX_CERTIFICATE_DER_BYTES:
        raise OpenSslCrosscheckError("certificate exceeds the configured size bound")


def _der_to_pem(payload: bytes) -> bytes:
    certificate = x509.load_der_x509_certificate(payload)
    return certificate.public_bytes(serialization.Encoding.PEM)


def _bound_text(raw: bytes) -> str:
    return raw[:_MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
