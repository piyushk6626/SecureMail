"""Atomic catalog publication for completed capture jobs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from securemail.adapters.persistence.writable_catalog import FilesystemCatalogPublisher
from securemail.ports.persistence import ReportRepositoryError


def test_publish_report_updates_catalog_atomically(tmp_path: Path) -> None:
    publisher = FilesystemCatalogPublisher(tmp_path)
    publisher.publish_report("case-a", b'{"schema_version":"securemail.report/v1"}')
    report = tmp_path / "case-a.report.json"
    catalog = json.loads((tmp_path / "catalog.json").read_text(encoding="utf-8"))
    assert report.read_bytes() == b'{"schema_version":"securemail.report/v1"}'
    assert catalog["reports"] == [{"case_id": "case-a", "report": "case-a.report.json"}]
    leftover = list(tmp_path.glob(".*.tmp"))
    assert leftover == []


def test_invalid_case_id_is_rejected(tmp_path: Path) -> None:
    publisher = FilesystemCatalogPublisher(tmp_path)
    with pytest.raises(ReportRepositoryError, match="invalid case ID"):
        publisher.publish_report("../escape", b"{}")
    assert list(tmp_path.glob("*")) == []
