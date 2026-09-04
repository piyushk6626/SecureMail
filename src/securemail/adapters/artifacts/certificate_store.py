"""Content-addressed DER store. Paths stay under a caller-provided root."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from securemail.domain.evidence.certificate import MAX_CERTIFICATE_DER_BYTES

_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class CertificateStoreError(Exception):
    """Raised when certificate bytes cannot be stored or retrieved safely."""


class CertificateStore:
    """SHA-256 addressed certificate bytes. Memory-only when `root` is omitted."""

    def __init__(self, root: Path | None = None) -> None:
        self._root = root.resolve() if root is not None else None
        self._memory: dict[str, bytes] = {}

    def put(self, payload: bytes) -> str:
        if not payload:
            raise CertificateStoreError("refusing to store empty certificate bytes")
        if len(payload) > MAX_CERTIFICATE_DER_BYTES:
            raise CertificateStoreError("certificate exceeds the configured size bound")
        digest = hashlib.sha256(payload).hexdigest()
        self._memory[digest] = payload
        if self._root is None:
            return digest
        path = self._path_for(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".der.tmp")
        tmp.write_bytes(payload)
        os.replace(tmp, path)
        stored = path.read_bytes()
        if hashlib.sha256(stored).hexdigest() != digest:
            raise CertificateStoreError("stored certificate digest does not match payload")
        return digest

    def get(self, digest: str) -> bytes:
        if not _DIGEST.fullmatch(digest):
            raise CertificateStoreError("certificate digest is not a SHA-256 hex string")
        cached = self._memory.get(digest)
        if cached is not None:
            return cached
        if self._root is None:
            raise KeyError(digest)
        path = self._path_for(digest)
        if not path.is_file():
            raise KeyError(digest)
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest:
            raise CertificateStoreError("on-disk certificate digest does not match its name")
        self._memory[digest] = payload
        return payload

    def _path_for(self, digest: str) -> Path:
        if self._root is None:
            raise CertificateStoreError("filesystem store requires a root directory")
        path = (self._root / f"{digest}.der").resolve()
        if not path.is_relative_to(self._root):
            raise CertificateStoreError("certificate path escaped the store root")
        return path
