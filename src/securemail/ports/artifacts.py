"""Protocol for content-addressed evidence storage."""

from typing import Protocol, runtime_checkable


@runtime_checkable
class ArtifactStore(Protocol):
    def put(self, payload: bytes) -> str:
        """Store `payload` and return its SHA-256 hex digest."""

    def get(self, digest: str) -> bytes:
        """Return bytes previously stored under `digest`."""
