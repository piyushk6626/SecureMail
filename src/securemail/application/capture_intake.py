"""Bounded PCAP/PCAPNG intake into the analysis job store."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import PurePosixPath

from pydantic import BaseModel, ConfigDict, Field

from securemail.application.run_analysis import PCAP_MAGICS, PCAPNG_MAGIC, InvalidCaptureError
from securemail.domain.evidence.run import PolicyProfile
from securemail.domain.jobs.models import (
    MAX_CAPTURE_BYTES,
    MAX_ORIGINAL_FILENAME_CHARS,
    AnalysisJob,
    AnalysisStage,
    AnalysisStatus,
)
from securemail.ports.jobs import AnalysisJobError, AnalysisJobStore, StorageQuotaError

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


class CaptureIntakeError(Exception):
    """Raised when a capture cannot be accepted."""


class CaptureTooLargeError(CaptureIntakeError):
    """Raised when the upload exceeds the configured byte cap."""


class CaptureIntakeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    original_filename: str = Field(min_length=1, max_length=MAX_ORIGINAL_FILENAME_CHARS)
    policy_profile: PolicyProfile = PolicyProfile.IETF_CURRENT
    expected_hostname: str | None = Field(default=None, max_length=253)
    case_id: str | None = Field(default=None, max_length=160)
    max_capture_bytes: int = Field(default=MAX_CAPTURE_BYTES, ge=1)


class _BoundedChunks:
    def __init__(self, chunks: Iterator[bytes], max_bytes: int) -> None:
        self._chunks = chunks
        self._max_bytes = max_bytes
        self.size = 0

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self._chunks:
            if not chunk:
                continue
            self.size += len(chunk)
            if self.size > self._max_bytes:
                raise CaptureTooLargeError(f"capture exceeds {self._max_bytes} bytes")
            yield chunk


def _basename(filename: str) -> str:
    name = PurePosixPath(filename.replace("\\", "/")).name
    if not name or name in {".", ".."}:
        raise CaptureIntakeError("capture filename is missing")
    if len(name) > MAX_ORIGINAL_FILENAME_CHARS:
        raise CaptureIntakeError("capture filename is too long")
    return name


def capture_format_for_filename(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".pcapng"):
        return "pcapng"
    if lower.endswith(".pcap"):
        return "pcap"
    raise InvalidCaptureError("capture must be a .pcap or .pcapng file")


def validate_magic(header: bytes, capture_format: str) -> None:
    if len(header) < 4:
        raise InvalidCaptureError("capture is empty or truncated")
    prefix = header[:4]
    if capture_format == "pcapng":
        if prefix != PCAPNG_MAGIC:
            raise InvalidCaptureError("file extension does not match PCAPNG magic")
        return
    if prefix not in PCAP_MAGICS:
        raise InvalidCaptureError("file extension does not match PCAP magic")


def allocate_run_id() -> str:
    return "r" + secrets.token_hex(8)


def case_id_for(*, requested: str | None, filename: str, digest: str) -> str:
    if requested is not None:
        text = requested.strip()
        if _ID_PATTERN.fullmatch(text) is None:
            raise CaptureIntakeError("case_id is not a valid identifier")
        return text
    stem = filename.rsplit(".", 1)[0]
    cleaned = _UNSAFE_NAME.sub("-", stem).strip("-._")
    if not cleaned or not cleaned[0].isalnum():
        cleaned = "cap"
    return f"{cleaned[:140]}-{digest[:8]}"


def ingest_capture(
    request: CaptureIntakeRequest,
    chunks: Iterator[bytes],
    *,
    job_store: AnalysisJobStore,
    now: datetime | None = None,
) -> AnalysisJob:
    """Stream, hash, and enqueue a capture. Duplicate intakes reuse the prior job."""

    filename = _basename(request.original_filename)
    capture_format = capture_format_for_filename(filename)
    bounded = _BoundedChunks(chunks, request.max_capture_bytes)
    staged = None
    try:
        staged = job_store.stage_capture(iter(bounded), capture_format=capture_format)
        validate_magic(staged.header, capture_format)
        duplicate = job_store.find_duplicate(
            capture_sha256=staged.sha256,
            policy_profile=request.policy_profile.value,
            expected_hostname=request.expected_hostname,
        )
        if duplicate is not None and (
            not duplicate.is_terminal or duplicate.status is AnalysisStatus.COMPLETED
        ):
            job_store.abort_staged(staged.upload_id)
            return duplicate
        created = now or datetime.now(UTC)
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        job = AnalysisJob(
            run_id=allocate_run_id(),
            case_id=case_id_for(requested=request.case_id, filename=filename, digest=staged.sha256),
            status=AnalysisStatus.QUEUED,
            stage=AnalysisStage.INTAKE,
            capture_sha256=staged.sha256,
            original_filename=filename,
            capture_format=capture_format,
            policy_profile=request.policy_profile.value,
            expected_hostname=request.expected_hostname,
            created_at=created,
            updated_at=created,
        )
        committed = job_store.commit_staged(staged.upload_id, job)
        staged = None
        return committed
    except StorageQuotaError:
        raise
    except AnalysisJobError as exc:
        raise CaptureIntakeError(str(exc)) from exc
    finally:
        if staged is not None:
            job_store.abort_staged(staged.upload_id)


def env_max_capture_bytes() -> int:
    raw = os.environ.get("SECUREMAIL_MAX_CAPTURE_BYTES")
    if raw is None or not raw.strip():
        return MAX_CAPTURE_BYTES
    try:
        value = int(raw)
    except ValueError as exc:
        raise CaptureIntakeError("SECUREMAIL_MAX_CAPTURE_BYTES must be an integer") from exc
    if value < 1:
        raise CaptureIntakeError("SECUREMAIL_MAX_CAPTURE_BYTES must be positive")
    return value


def sha256_chunks(chunks: Iterator[bytes]) -> str:
    digest = hashlib.sha256()
    for chunk in chunks:
        digest.update(chunk)
    return digest.hexdigest()
