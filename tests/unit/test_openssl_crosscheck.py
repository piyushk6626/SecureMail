"""OpenSSL CLI vs cryptography path-validation differential (test-only adapter)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from tests.unit.test_chain_validation import _pki

from securemail.adapters.pki.openssl_crosscheck import (
    openssl_available,
    openssl_verify_chain,
    resolve_openssl_binary,
)
from securemail.domain.policies.pki.chain_validation import (
    ChainValidationInput,
    build_trust_snapshot,
    validate_certificate_path,
)

# Documented disagreements: (scenario, instant_label) -> reason. Keep empty unless a
# real OpenSSL vs cryptography difference is observed and explained.
_ALLOWED_DISAGREEMENTS: dict[tuple[str, str], str] = {}


pytestmark = pytest.mark.skipif(
    not openssl_available(),
    reason="Homebrew/OpenSSL 3.x is required for the Step 6 differential test",
)


def _trust_pem(tmp_path: Path, root_der: bytes) -> Path:
    cert = x509.load_der_x509_certificate(root_der)
    path = tmp_path / "trust.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def test_openssl_binary_is_not_libressl() -> None:
    binary = resolve_openssl_binary()
    assert openssl_available(binary)


def test_openssl_agrees_with_cryptography_for_trusted_and_broken_chains(tmp_path: Path) -> None:
    root, intermediate, leaf = _pki()
    snapshot = build_trust_snapshot([root], profile_id="test", digest="a" * 64)
    trust_pem = _trust_pem(tmp_path, root.public_bytes(serialization.Encoding.DER))
    instant = datetime(2026, 9, 4, tzinfo=UTC)
    cases = {
        "trusted": (leaf, (intermediate,)),
        "missing_intermediate": (leaf, ()),
    }
    for name, (ee, intermediates) in cases.items():
        python = validate_certificate_path(
            ChainValidationInput(
                leaf=ee,
                intermediates=intermediates,
                trust_store=snapshot,
                verification_time=instant,
            )
        )
        openssl = openssl_verify_chain(
            leaf_der=ee.public_bytes(serialization.Encoding.DER),
            intermediate_ders=[
                item.public_bytes(serialization.Encoding.DER) for item in intermediates
            ],
            trust_pem_path=trust_pem,
            verification_time=instant,
        )
        if python.valid != openssl.path_valid:
            key = (name, "analysis")
            assert key in _ALLOWED_DISAGREEMENTS, (
                f"cryptography and OpenSSL disagree on {name}: "
                f"python={python.valid} openssl={openssl.path_valid} "
                f"reasons={python.reason_codes} stderr={openssl.stderr}"
            )
        else:
            assert python.valid == openssl.path_valid
