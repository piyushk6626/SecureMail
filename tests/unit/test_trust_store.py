"""Pinned trust-store snapshot bounds and digest stability."""

from pathlib import Path

import pytest

from securemail.adapters.pki.trust_store import (
    TrustStoreError,
    load_trust_store_snapshot,
    trust_store_digest,
)
from securemail.domain.policies.pki.chain_validation import TRUST_PROFILE_ID


def test_default_snapshot_loads_lab_and_public_roots() -> None:
    snapshot = load_trust_store_snapshot()
    assert snapshot.profile_id == TRUST_PROFILE_ID
    assert snapshot.digest == trust_store_digest()
    assert len(snapshot.digest) == 64
    names = {item.subject.rfc4514_string() for item in snapshot.anchors}
    assert any("SecureMail Lab Root CA" in name for name in names)
    assert any("USERTrust RSA Certification Authority" in name for name in names)


def test_digest_is_sha256_of_file_bytes() -> None:
    digest = trust_store_digest()
    snapshot = load_trust_store_snapshot()
    assert snapshot.digest == digest
    again = load_trust_store_snapshot()
    assert again.digest == digest


def test_rejects_missing_empty_and_oversized_snapshots(tmp_path: Path) -> None:
    missing = tmp_path / "missing.pem"
    with pytest.raises(TrustStoreError):
        load_trust_store_snapshot(missing)
    empty = tmp_path / "empty.pem"
    empty.write_text("# no certificates\n", encoding="utf-8")
    with pytest.raises(TrustStoreError):
        load_trust_store_snapshot(empty)
    huge = tmp_path / "huge.pem"
    huge.write_bytes(b"A" * (2_000_001))
    with pytest.raises(TrustStoreError):
        load_trust_store_snapshot(huge)
