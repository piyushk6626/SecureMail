"""RFC 8785 canonicalization and SHA-256 for canonical reports."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

import rfc8785


class CanonicalJsonError(ValueError):
    """Raised when a report payload cannot be canonicalized."""


def canonicalize(payload: Mapping[str, Any] | list[Any] | dict[str, Any]) -> bytes:
    """Return RFC 8785 JCS bytes. Does not mutate `payload`."""

    try:
        return rfc8785.dumps(payload)
    except rfc8785.CanonicalizationError as exc:
        raise CanonicalJsonError(str(exc)) from exc


def sha256_digest(canonical_bytes: bytes) -> str:
    return hashlib.sha256(canonical_bytes).hexdigest()
