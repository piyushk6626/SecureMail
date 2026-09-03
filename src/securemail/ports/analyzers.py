"""Protocol interfaces for sandboxed Zeek and TShark runners."""

from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict


class AnalyzerError(Exception):
    """Raised by analyzer adapters when a sandboxed run cannot complete."""


class ZeekRunResult(BaseModel):
    """Structured Zeek output plus the digests actually used."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    image_digest: str
    analyzer_bundle_digest: str
    logs: dict[str, list[dict[str, object]]]


class TSharkRunResult(BaseModel):
    """Bounded TShark JSON frames plus the image digest actually used."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    image_digest: str
    frames: list[dict[str, object]]


@runtime_checkable
class ZeekRunner(Protocol):
    def run(self, capture_path: Path) -> ZeekRunResult:
        """Analyze `capture_path` and return JSON logs plus digests."""


@runtime_checkable
class TSharkRunner(Protocol):
    def run(self, capture_path: Path) -> TSharkRunResult:
        """Run a bounded TShark pass over `capture_path`."""
