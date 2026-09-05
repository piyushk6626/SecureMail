"""Filesystem job-store boundary for capture analysis."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from securemail.domain.jobs.models import AnalysisJob, AnalysisStage, AnalysisStatus


class AnalysisJobError(Exception):
    """Raised when a job cannot be stored or loaded safely."""


class JobNotFoundError(AnalysisJobError):
    """Raised when ``run_id`` is unknown."""


class JobConflictError(AnalysisJobError):
    """Raised when a job cannot change state as requested."""


class StorageQuotaError(AnalysisJobError):
    """Raised when job count or disk quota would be exceeded."""


class StagedCapture(BaseModel):
    """Quarantined upload identified only by generated IDs and hashes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    upload_id: str = Field(min_length=1, max_length=64)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)
    header: bytes = Field(min_length=0, max_length=4)


@runtime_checkable
class AnalysisJobStore(Protocol):
    """Durable jobs, captures, and rendered artifacts. Paths stay inside the adapter."""

    def stage_capture(self, chunks: Iterator[bytes], *, capture_format: str) -> StagedCapture:
        """Stream bytes into quarantine while hashing. Caller must commit or abort."""

    def abort_staged(self, upload_id: str) -> None:
        """Delete a quarantined upload. Missing IDs are ignored."""

    def commit_staged(self, upload_id: str, job: AnalysisJob) -> AnalysisJob:
        """Move a staged capture into ``jobs/{run_id}`` and persist ``status.json``."""

    def get_job(self, run_id: str) -> AnalysisJob | None:
        """Return the job record, or ``None``."""

    def find_duplicate(
        self,
        *,
        capture_sha256: str,
        policy_profile: str,
        expected_hostname: str | None,
    ) -> AnalysisJob | None:
        """Return an in-flight or completed job with the same intake identity."""

    def list_jobs(self) -> tuple[AnalysisJob, ...]:
        """All jobs, deterministic order."""

    def claim_next(self) -> AnalysisJob | None:
        """Atomically claim the oldest queued job for the worker."""

    def update_job(
        self,
        run_id: str,
        *,
        status: AnalysisStatus | None = None,
        stage: AnalysisStage | None = None,
        error_message: str | None = None,
        artifacts: object | None = None,
        cancel_requested: bool | None = None,
    ) -> AnalysisJob:
        """Patch job fields. ``artifacts`` is ``ArtifactAvailability`` when set."""

    def request_cancel(self, run_id: str) -> AnalysisJob:
        """Mark cancel requested. Terminal jobs raise ``JobConflictError``."""

    def is_cancel_requested(self, run_id: str) -> bool:
        """True when the worker should stop after the current stage."""

    def capture_path(self, run_id: str) -> Path:
        """Absolute path of the stored capture. Worker-only."""

    def write_artifact(self, run_id: str, name: str, payload: bytes) -> None:
        """Store ``report.json``, ``report.html``, or ``report.pdf``."""

    def read_artifact(self, run_id: str, name: str) -> bytes | None:
        """Return artifact bytes, or ``None`` if missing."""
