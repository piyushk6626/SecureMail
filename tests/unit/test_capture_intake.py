"""Capture intake validation, bounds, and duplicate reuse."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from securemail.adapters.persistence.job_store import FilesystemJobStore
from securemail.application.capture_intake import (
    CaptureIntakeRequest,
    CaptureTooLargeError,
    ingest_capture,
)
from securemail.application.run_analysis import PCAPNG_MAGIC, InvalidCaptureError
from securemail.domain.jobs.models import AnalysisStatus

PCAP_LE = b"\xd4\xc3\xb2\xa1"


def _store(tmp_path: Path) -> FilesystemJobStore:
    return FilesystemJobStore(tmp_path)


def test_pcapng_upload_is_queued(tmp_path: Path) -> None:
    job = ingest_capture(
        CaptureIntakeRequest(original_filename="mail.pcapng"),
        iter([PCAPNG_MAGIC, b"\x00\x01"]),
        job_store=_store(tmp_path),
    )
    assert job.status is AnalysisStatus.QUEUED
    assert job.capture_format == "pcapng"
    assert job.capture_sha256 is not None
    assert job.case_id.startswith("mail-")
    assert (_store(tmp_path).capture_path(job.run_id)).is_file()


def test_extension_magic_mismatch_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(InvalidCaptureError, match="PCAPNG magic"):
        ingest_capture(
            CaptureIntakeRequest(original_filename="mail.pcapng"),
            iter([PCAP_LE, b"\x00"]),
            job_store=_store(tmp_path),
        )
    assert list((tmp_path / "quarantine").glob("*.part")) == []


def test_oversize_upload_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(CaptureTooLargeError):
        ingest_capture(
            CaptureIntakeRequest(original_filename="mail.pcapng", max_capture_bytes=8),
            iter([PCAPNG_MAGIC, b"\x00" * 16]),
            job_store=_store(tmp_path),
        )


def test_duplicate_upload_reuses_queued_job(tmp_path: Path) -> None:
    store = _store(tmp_path)
    payload = [PCAPNG_MAGIC, b"\x01\x02"]
    first = ingest_capture(
        CaptureIntakeRequest(original_filename="dup.pcapng"),
        iter(payload),
        job_store=store,
    )
    second = ingest_capture(
        CaptureIntakeRequest(original_filename="dup.pcapng"),
        iter(payload),
        job_store=store,
    )
    assert first.run_id == second.run_id
    assert len(store.list_jobs()) == 1


def test_disconnect_during_upload_cleans_quarantine(tmp_path: Path) -> None:
    def chunks() -> Iterator[bytes]:
        yield PCAPNG_MAGIC
        raise RuntimeError("client disconnect")

    with pytest.raises(RuntimeError, match="client disconnect"):
        ingest_capture(
            CaptureIntakeRequest(original_filename="mail.pcapng"),
            chunks(),
            job_store=_store(tmp_path),
        )
    quarantine = tmp_path / "quarantine"
    leftover = list(quarantine.glob("*")) if quarantine.exists() else []
    assert leftover == []
    assert list(_store(tmp_path).list_jobs()) == []


def test_path_in_filename_is_stripped(tmp_path: Path) -> None:
    job = ingest_capture(
        CaptureIntakeRequest(original_filename="../../etc/passwd.pcapng"),
        iter([PCAPNG_MAGIC, b"\x00"]),
        job_store=_store(tmp_path),
    )
    assert job.original_filename == "passwd.pcapng"
    assert ".." not in str(_store(tmp_path).capture_path(job.run_id))
