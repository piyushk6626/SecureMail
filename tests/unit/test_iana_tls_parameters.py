"""IANA TLS Parameters snapshot loading and lookups."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from securemail.adapters.reference_data.iana_tls_parameters import (
    IanaTlsParametersError,
    iana_snapshot_digest,
    load_iana_tls_parameters,
)
from securemail.domain.policies.tls.key_exchange import empty_tls_parameter_index


def test_snapshot_contains_required_suites_and_groups() -> None:
    index = load_iana_tls_parameters()
    assert index.digest == iana_snapshot_digest()
    assert index.digest != empty_tls_parameter_index().digest
    assert index.cipher_code("TLS_AES_128_GCM_SHA256") == "0x1301"
    assert index.cipher_code("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") == "0xC02F"
    assert index.cipher_code("TLS_RSA_WITH_AES_128_CBC_SHA") == "0x002F"
    assert index.cipher_code("TLS_RSA_WITH_RC4_128_SHA") == "0x0005"
    assert index.cipher_code("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA") == "0xC004"
    assert index.group_name(29) == "x25519"
    assert index.group_name(23) == "secp256r1"
    assert index.group_name(256) == "ffdhe2048"
    assert index.group_name(4588) == "X25519MLKEM768"
    assert index.group_code("x25519") == 29


def test_loader_rejects_oversized_and_malformed_snapshots(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    with pytest.raises(IanaTlsParametersError):
        load_iana_tls_parameters(missing)

    huge = tmp_path / "huge.json"
    huge.write_bytes(b"{" + b"a" * 1_000_001)
    with pytest.raises(IanaTlsParametersError):
        load_iana_tls_parameters(huge)

    malformed = tmp_path / "bad.json"
    malformed.write_text("{not json", encoding="utf-8")
    with pytest.raises(IanaTlsParametersError):
        load_iana_tls_parameters(malformed)

    incomplete = tmp_path / "incomplete.json"
    incomplete.write_text(json.dumps({"cipher_suites": []}) + "\n", encoding="utf-8")
    with pytest.raises(IanaTlsParametersError):
        load_iana_tls_parameters(incomplete)
