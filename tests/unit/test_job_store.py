"""Filesystem job store: quarantine, cancel, artifacts, and quota."""

from __future__ import annotations

from pathlib import Path

import pytest

from securemail.adapters.persistence.job_store import FilesystemJobStore
from securemail.application.capture_intake import CaptureIntakeRequest, ingest_capture
from securemail.application.run_analysis import PCAPNG_MAGIC
from securemail.domain.jobs.models import AnalysisStage, AnalysisStatus, ArtifactAvailability
from securemail.ports.jobs import AnalysisJobError, JobConflictError, StorageQuotaError


def test_claim_cancel_and_artifacts(tmp_path: Path) -> None:
    store = FilesystemJobStore(tmp_path)
    job = ingest_capture(
        CaptureIntakeRequest(original_filename="mail.pcapng"),
        iter([PCAPNG_MAGIC, b"\x00"]),
        job_store=store,
    )
    claimed = store.claim_next()
    assert claimed is not None
    assert claimed.run_id == job.run_id
    assert claimed.status is AnalysisStatus.RUNNING
    store.update_job(job.run_id, stage=AnalysisStage.REPORT_RENDERING)
    store.write_artifact(job.run_id, "report.json", b'{"ok":true}')
    payload = store.read_artifact(job.run_id, "report.json")
    assert payload == b'{"ok":true}'
    cancelled = store.request_cancel(job.run_id)
    assert cancelled.cancel_requested is True
    assert store.is_cancel_requested(job.run_id) is True


def test_cancel_queued_job_is_terminal(tmp_path: Path) -> None:
    store = FilesystemJobStore(tmp_path)
    job = ingest_capture(
        CaptureIntakeRequest(original_filename="mail.pcapng"),
        iter([PCAPNG_MAGIC, b"\x00"]),
        job_store=store,
    )
    cancelled = store.request_cancel(job.run_id)
    assert cancelled.status is AnalysisStatus.CANCELLED
    with pytest.raises(JobConflictError):
        store.request_cancel(job.run_id)
    assert store.claim_next() is None


def test_job_count_quota(tmp_path: Path) -> None:
    store = FilesystemJobStore(tmp_path, max_jobs=1)
    ingest_capture(
        CaptureIntakeRequest(original_filename="one.pcapng"),
        iter([PCAPNG_MAGIC, b"\x01"]),
        job_store=store,
    )
    with pytest.raises(StorageQuotaError):
        ingest_capture(
            CaptureIntakeRequest(original_filename="two.pcapng"),
            iter([PCAPNG_MAGIC, b"\x02"]),
            job_store=store,
        )


def test_symlink_capture_path_is_rejected(tmp_path: Path) -> None:
    store = FilesystemJobStore(tmp_path)
    job = ingest_capture(
        CaptureIntakeRequest(original_filename="mail.pcapng"),
        iter([PCAPNG_MAGIC, b"\x00"]),
        job_store=store,
    )
    capture = store.capture_path(job.run_id)
    outside = tmp_path / "outside"
    outside.write_bytes(PCAPNG_MAGIC)
    capture.unlink()
    capture.symlink_to(outside)
    with pytest.raises(AnalysisJobError):
        store.capture_path(job.run_id)


def test_completed_artifacts_flag(tmp_path: Path) -> None:
    store = FilesystemJobStore(tmp_path)
    job = ingest_capture(
        CaptureIntakeRequest(original_filename="mail.pcapng"),
        iter([PCAPNG_MAGIC, b"\x00"]),
        job_store=store,
    )
    store.claim_next()
    updated = store.update_job(
        job.run_id,
        status=AnalysisStatus.COMPLETED,
        artifacts=ArtifactAvailability(json=True, html=True, pdf=True),
    )
    assert updated.artifacts.html is True


def test_job_survives_store_reopen(tmp_path: Path) -> None:
    first = FilesystemJobStore(tmp_path)
    job = ingest_capture(
        CaptureIntakeRequest(original_filename="mail.pcapng"),
        iter([PCAPNG_MAGIC, b"\x00"]),
        job_store=first,
    )
    recovered = FilesystemJobStore(tmp_path)
    claimed = recovered.claim_next()
    assert claimed is not None
    assert claimed.run_id == job.run_id
    assert claimed.status is AnalysisStatus.RUNNING
