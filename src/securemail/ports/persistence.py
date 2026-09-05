"""Read-only persistence boundary for canonical reports."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

MAX_REPORT_BYTES = 8 * 1024 * 1024


class ReportCatalogEntry(BaseModel):
    """Safe catalog metadata. Filesystem paths never cross this boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(min_length=1, max_length=160)
    size_bytes: int = Field(ge=0)


class ReportRepositoryError(Exception):
    """Raised when the configured report catalog is unsafe or invalid."""


@runtime_checkable
class ReportRepository(Protocol):
    """Return bounded report bytes and path-free catalog entries."""

    def list_reports(self) -> tuple[ReportCatalogEntry, ...]:
        """List explicitly cataloged case reports in deterministic order."""

    def get_report(self, case_id: str) -> bytes | None:
        """Return raw report bytes for an explicit case ID, or ``None``."""


@runtime_checkable
class CatalogPublisher(Protocol):
    """Atomically publish a canonical report into the Step 11 catalog."""

    def publish_report(self, case_id: str, canonical_bytes: bytes) -> None:
        """Replace or insert ``case_id`` and fsync the catalog + report file."""
