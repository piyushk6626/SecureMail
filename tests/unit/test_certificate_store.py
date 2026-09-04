"""Content-addressed certificate store bounds and path safety."""

from pathlib import Path

import pytest

from securemail.adapters.artifacts.certificate_store import CertificateStore, CertificateStoreError
from securemail.domain.evidence.certificate import MAX_CERTIFICATE_DER_BYTES


def test_put_get_round_trip_and_dedup(tmp_path: Path) -> None:
    store = CertificateStore(root=tmp_path)
    payload = b"\x30\x03\x02\x01\x01"
    first = store.put(payload)
    second = store.put(payload)
    assert first == second
    assert store.get(first) == payload
    assert (tmp_path / f"{first}.der").is_file()


def test_rejects_oversized_and_empty_payloads(tmp_path: Path) -> None:
    store = CertificateStore(root=tmp_path)
    with pytest.raises(CertificateStoreError):
        store.put(b"")
    with pytest.raises(CertificateStoreError):
        store.put(b"\x00" * (MAX_CERTIFICATE_DER_BYTES + 1))


def test_rejects_unknown_and_invalid_digests(tmp_path: Path) -> None:
    store = CertificateStore(root=tmp_path)
    with pytest.raises(CertificateStoreError):
        store.get("../not-a-digest")
    with pytest.raises(KeyError):
        store.get("a" * 64)
