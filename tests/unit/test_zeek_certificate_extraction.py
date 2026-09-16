"""Bounds and deduplication for Zeek's extracted certificate files."""

from hashlib import sha256
from pathlib import Path

import pytest

from securemail.adapters.analyzers.bundle_lock import AnalyzerExecutionError
from securemail.adapters.analyzers.zeek_runner import _read_extracted_certificates
from securemail.domain.evidence.certificate import MAX_EXTRACTED_CERTIFICATE_FILES_PER_RUN


def test_repeated_der_files_count_once_toward_certificate_limit(tmp_path: Path) -> None:
    certificate_dir = tmp_path / "certs"
    certificate_dir.mkdir()
    payload = b"repeated-certificate"
    for index in range(257):
        (certificate_dir / f"F{index:03d}.der").write_bytes(payload)

    extracted = _read_extracted_certificates(tmp_path, consumed_bytes=0)

    assert len(extracted) == 1
    assert extracted[0].fuid == "F000"
    assert extracted[0].sha256 == sha256(payload).hexdigest()


def test_raw_certificate_file_count_remains_bounded(tmp_path: Path) -> None:
    certificate_dir = tmp_path / "certs"
    certificate_dir.mkdir()
    for index in range(MAX_EXTRACTED_CERTIFICATE_FILES_PER_RUN + 1):
        (certificate_dir / f"F{index:04d}.der").write_bytes(b"")

    with pytest.raises(AnalyzerExecutionError, match="too many certificate files"):
        _read_extracted_certificates(tmp_path, consumed_bytes=0)
