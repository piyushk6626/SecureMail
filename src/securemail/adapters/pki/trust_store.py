"""Load the pinned offline trust-store snapshot. No network I/O."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Final

from cryptography import x509

from securemail.domain.policies.pki.chain_validation import (
    TRUST_PROFILE_ID,
    TrustStoreSnapshot,
    build_trust_snapshot,
)

_DEFAULT_PATH = Path(__file__).with_name("trust-store-snapshot.pem")
_MAX_FILE_BYTES: Final[int] = 2_000_000
_MAX_ANCHORS: Final[int] = 256


class TrustStoreError(ValueError):
    """Raised when the checked-in trust-store snapshot is missing or malformed."""


def trust_store_digest(path: Path | None = None) -> str:
    """SHA-256 of the snapshot file bytes."""

    snapshot = path if path is not None else _DEFAULT_PATH
    return hashlib.sha256(_read_bounded(snapshot)).hexdigest()


def load_trust_store_snapshot(path: Path | None = None) -> TrustStoreSnapshot:
    """Parse PEM anchors into a domain snapshot with a stable digest."""

    snapshot = path if path is not None else _DEFAULT_PATH
    raw = _read_bounded(snapshot)
    digest = hashlib.sha256(raw).hexdigest()
    try:
        anchors = x509.load_pem_x509_certificates(raw)
    except ValueError as exc:
        raise TrustStoreError("trust-store snapshot is not valid PEM") from exc
    if not anchors:
        raise TrustStoreError("trust-store snapshot contains no certificates")
    if len(anchors) > _MAX_ANCHORS:
        raise TrustStoreError("trust-store snapshot exceeds the configured anchor bound")
    return build_trust_snapshot(anchors, profile_id=TRUST_PROFILE_ID, digest=digest)


def _read_bounded(path: Path) -> bytes:
    if not path.is_file():
        raise TrustStoreError(f"trust-store snapshot not found: {path}")
    if path.stat().st_size > _MAX_FILE_BYTES:
        raise TrustStoreError("trust-store snapshot exceeds the configured size bound")
    return path.read_bytes()
