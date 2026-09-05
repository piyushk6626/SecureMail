"""Filesystem job store: quarantine, status, captures, and artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from securemail.domain.jobs.models import (
    MAX_DATA_ROOT_BYTES,
    MAX_HTML_BYTES,
    MAX_JOB_COUNT,
    MAX_PDF_BYTES,
    AnalysisJob,
    AnalysisStage,
    AnalysisStatus,
    ArtifactAvailability,
)
from securemail.ports.jobs import (
    AnalysisJobError,
    JobConflictError,
    JobNotFoundError,
    StagedCapture,
    StorageQuotaError,
)
from securemail.ports.persistence import MAX_REPORT_BYTES

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
_ARTIFACT_LIMITS = {
    "report.json": MAX_REPORT_BYTES,
    "report.html": MAX_HTML_BYTES,
    "report.pdf": MAX_PDF_BYTES,
}
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class FilesystemJobStore:
    """Job records under ``{root}/jobs`` and quarantined uploads under ``quarantine``."""

    def __init__(
        self,
        root: Path,
        *,
        max_jobs: int = MAX_JOB_COUNT,
        max_data_bytes: int = MAX_DATA_ROOT_BYTES,
    ) -> None:
        if max_jobs < 1:
            raise ValueError("max_jobs must be positive")
        if max_data_bytes < 1:
            raise ValueError("max_data_bytes must be positive")
        self._root = root.expanduser().absolute()
        self._max_jobs = max_jobs
        self._max_data_bytes = max_data_bytes

    def stage_capture(self, chunks: Iterator[bytes], *, capture_format: str) -> StagedCapture:
        if capture_format not in {"pcap", "pcapng"}:
            raise AnalysisJobError("unsupported capture format")
        self._ensure_layout()
        upload_id = "u" + secrets.token_hex(8)
        path = self._quarantine_dir() / f"{upload_id}.part"
        digest = hashlib.sha256()
        header = b""
        size = 0
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise AnalysisJobError("cannot create quarantine file") from exc
        try:
            for chunk in chunks:
                size += len(chunk)
                digest.update(chunk)
                if len(header) < 4:
                    header += chunk[: 4 - len(header)]
                written = 0
                while written < len(chunk):
                    written += os.write(descriptor, chunk[written:])
            os.fsync(descriptor)
        except Exception:
            os.close(descriptor)
            path.unlink(missing_ok=True)
            raise
        else:
            os.close(descriptor)
        if size == 0:
            path.unlink(missing_ok=True)
            raise AnalysisJobError("capture is empty")
        return StagedCapture(
            upload_id=upload_id,
            sha256=digest.hexdigest(),
            size_bytes=size,
            header=header[:4],
        )

    def abort_staged(self, upload_id: str) -> None:
        if _ID_PATTERN.fullmatch(upload_id) is None:
            return
        path = self._quarantine_dir() / f"{upload_id}.part"
        path.unlink(missing_ok=True)

    def commit_staged(self, upload_id: str, job: AnalysisJob) -> AnalysisJob:
        if _ID_PATTERN.fullmatch(upload_id) is None or _ID_PATTERN.fullmatch(job.run_id) is None:
            raise AnalysisJobError("invalid upload or run identifier")
        self._ensure_layout()
        staged = self._quarantine_dir() / f"{upload_id}.part"
        if not staged.is_file() or staged.is_symlink():
            raise AnalysisJobError("staged capture is missing")
        jobs = self._jobs_dir()
        existing = [path for path in jobs.iterdir() if path.is_dir() and not path.is_symlink()]
        if len(existing) >= self._max_jobs:
            raise StorageQuotaError(f"job catalog exceeds {self._max_jobs} entries")
        used = self._usage_bytes() + staged.stat().st_size
        if used > self._max_data_bytes:
            raise StorageQuotaError(f"data root exceeds {self._max_data_bytes} bytes")
        job_dir = jobs / job.run_id
        try:
            job_dir.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise AnalysisJobError("duplicate run_id") from exc
        capture_name = f"capture.{job.capture_format}"
        target = job_dir / capture_name
        try:
            os.replace(staged, target)
        except OSError as exc:
            self._remove_tree(job_dir)
            raise AnalysisJobError("cannot store capture") from exc
        (job_dir / "artifacts").mkdir(mode=0o700)
        self._write_status(job_dir, job)
        return job

    def get_job(self, run_id: str) -> AnalysisJob | None:
        path = self._status_path(run_id)
        if path is None:
            return None
        return self._read_status(path)

    def find_duplicate(
        self,
        *,
        capture_sha256: str,
        policy_profile: str,
        expected_hostname: str | None,
    ) -> AnalysisJob | None:
        matches = [
            job
            for job in self.list_jobs()
            if job.capture_sha256 == capture_sha256
            and job.policy_profile == policy_profile
            and job.expected_hostname == expected_hostname
            and (not job.is_terminal or job.status is AnalysisStatus.COMPLETED)
        ]
        if not matches:
            return None
        matches.sort(key=lambda item: (item.created_at, item.run_id))
        return matches[-1]

    def list_jobs(self) -> tuple[AnalysisJob, ...]:
        if not self._jobs_dir().exists():
            return ()
        jobs: list[AnalysisJob] = []
        for path in sorted(self._jobs_dir().iterdir()):
            if not path.is_dir() or path.is_symlink():
                continue
            status = path / "status.json"
            if status.is_file() and not status.is_symlink():
                jobs.append(self._read_status(status))
        return tuple(jobs)

    def claim_next(self) -> AnalysisJob | None:
        queued = [
            job
            for job in self.list_jobs()
            if job.status is AnalysisStatus.QUEUED and not job.cancel_requested
        ]
        queued.sort(key=lambda item: (item.created_at, item.run_id))
        for job in queued:
            try:
                return self.update_job(job.run_id, status=AnalysisStatus.RUNNING)
            except JobConflictError:
                continue
        cancelled = [
            job
            for job in self.list_jobs()
            if job.status is AnalysisStatus.QUEUED and job.cancel_requested
        ]
        for job in cancelled:
            self.update_job(job.run_id, status=AnalysisStatus.CANCELLED)
        return None

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
        current = self.get_job(run_id)
        if current is None:
            raise JobNotFoundError("analysis run not found")
        updates: dict[str, object] = {"updated_at": datetime.now(UTC)}
        if status is not None:
            if current.is_terminal:
                raise JobConflictError("analysis run is already terminal")
            updates["status"] = status
        if stage is not None:
            updates["stage"] = stage
        if error_message is not None:
            updates["error_message"] = error_message
        if artifacts is not None:
            if not isinstance(artifacts, ArtifactAvailability):
                raise AnalysisJobError("invalid artifact availability")
            updates["artifacts"] = artifacts
        if cancel_requested is not None:
            updates["cancel_requested"] = cancel_requested
            job_dir = self._job_dir(run_id)
            flag = job_dir / "cancel.flag"
            if cancel_requested:
                flag.write_text("1\n", encoding="utf-8")
            elif flag.exists():
                flag.unlink()
        updated = current.model_copy(update=updates)
        self._write_status(self._job_dir(run_id), updated)
        return updated

    def request_cancel(self, run_id: str) -> AnalysisJob:
        current = self.get_job(run_id)
        if current is None:
            raise JobNotFoundError("analysis run not found")
        if current.is_terminal:
            raise JobConflictError("analysis run is already terminal")
        if current.status is AnalysisStatus.QUEUED:
            return self.update_job(
                run_id,
                status=AnalysisStatus.CANCELLED,
                cancel_requested=True,
            )
        return self.update_job(run_id, cancel_requested=True)

    def is_cancel_requested(self, run_id: str) -> bool:
        job = self.get_job(run_id)
        if job is None:
            return False
        flag = self._job_dir(run_id) / "cancel.flag"
        return job.cancel_requested or (flag.is_file() and not flag.is_symlink())

    def capture_path(self, run_id: str) -> Path:
        job = self.get_job(run_id)
        if job is None:
            raise JobNotFoundError("analysis run not found")
        path = self._job_dir(run_id) / f"capture.{job.capture_format}"
        if path.is_symlink() or not path.is_file():
            raise AnalysisJobError("stored capture is missing")
        return path

    def write_artifact(self, run_id: str, name: str, payload: bytes) -> None:
        if name not in _ARTIFACT_LIMITS:
            raise AnalysisJobError("unsupported artifact name")
        if len(payload) > _ARTIFACT_LIMITS[name]:
            raise AnalysisJobError(f"{name} exceeds {_ARTIFACT_LIMITS[name]} bytes")
        if self.get_job(run_id) is None:
            raise JobNotFoundError("analysis run not found")
        directory = self._job_dir(run_id) / "artifacts"
        directory.mkdir(mode=0o700, exist_ok=True)
        target = directory / name
        tmp = directory / f".{name}.tmp"
        tmp.write_bytes(payload)
        os.replace(tmp, target)

    def read_artifact(self, run_id: str, name: str) -> bytes | None:
        if name not in _ARTIFACT_LIMITS:
            raise AnalysisJobError("unsupported artifact name")
        if self.get_job(run_id) is None:
            raise JobNotFoundError("analysis run not found")
        path = self._job_dir(run_id) / "artifacts" / name
        if not path.exists():
            return None
        limit = _ARTIFACT_LIMITS[name]
        return self._read_file(path, limit)

    def _ensure_layout(self) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        if self._root.is_symlink() or not self._root.is_dir():
            raise AnalysisJobError("data root must be a non-symlink directory")
        self._jobs_dir().mkdir(mode=0o700, exist_ok=True)
        self._quarantine_dir().mkdir(mode=0o700, exist_ok=True)

    def _jobs_dir(self) -> Path:
        return self._root / "jobs"

    def _quarantine_dir(self) -> Path:
        return self._root / "quarantine"

    def _job_dir(self, run_id: str) -> Path:
        if _ID_PATTERN.fullmatch(run_id) is None:
            raise AnalysisJobError("invalid run identifier")
        path = self._jobs_dir() / run_id
        if path.is_symlink() or not path.is_dir():
            raise JobNotFoundError("analysis run not found")
        return path

    def _status_path(self, run_id: str) -> Path | None:
        if _ID_PATTERN.fullmatch(run_id) is None:
            return None
        candidate = self._jobs_dir() / run_id / "status.json"
        if not candidate.exists():
            return None
        if candidate.is_symlink() or not candidate.is_file():
            raise AnalysisJobError("job status must be a regular file")
        return candidate

    def _write_status(self, job_dir: Path, job: AnalysisJob) -> None:
        payload = job.model_dump(mode="json")
        raw = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        tmp = job_dir / ".status.json.tmp"
        tmp.write_text(raw, encoding="utf-8")
        os.replace(tmp, job_dir / "status.json")

    def _read_status(self, path: Path) -> AnalysisJob:
        raw = self._read_file(path, 64 * 1024)
        try:
            return AnalysisJob.model_validate(json.loads(raw.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
            raise AnalysisJobError("job status is not valid JSON") from exc

    def _usage_bytes(self) -> int:
        total = 0
        for directory in (self._jobs_dir(), self._quarantine_dir()):
            if not directory.exists():
                continue
            for path in directory.rglob("*"):
                if path.is_symlink() or not path.is_file():
                    continue
                total += path.stat().st_size
        return total

    @staticmethod
    def _remove_tree(path: Path) -> None:
        if path.is_symlink() or not path.exists():
            return
        for child in path.rglob("*"):
            if child.is_file() or child.is_symlink():
                child.unlink(missing_ok=True)
        for child in sorted(path.rglob("*"), reverse=True):
            if child.is_dir() and not child.is_symlink():
                child.rmdir()
        path.rmdir()

    @staticmethod
    def _read_file(path: Path, limit: int) -> bytes:
        flags = os.O_RDONLY | _NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise AnalysisJobError("cannot open job file") from exc
        try:
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise AnalysisJobError("job file must be a regular file")
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
        finally:
            os.close(descriptor)
        if len(payload) > limit:
            raise AnalysisJobError("job file exceeds limit")
        return payload
