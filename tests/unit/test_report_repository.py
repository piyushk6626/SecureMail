"""Filesystem report repository boundary and traversal tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from securemail.adapters.persistence.report_repository import FilesystemReportRepository
from securemail.ports.persistence import ReportRepositoryError


def _write_catalog(root: Path, reports: list[dict[str, str]]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "catalog.json").write_text(
        json.dumps(
            {
                "schema_version": "securemail.report-catalog/v1",
                "reports": reports,
            }
        ),
        encoding="utf-8",
    )


def test_repository_returns_explicit_path_free_entries(tmp_path: Path) -> None:
    (tmp_path / "case.report.json").write_bytes(b"{}")
    _write_catalog(tmp_path, [{"case_id": "case_one", "report": "case.report.json"}])
    repository = FilesystemReportRepository(tmp_path)
    assert repository.list_reports()[0].model_dump() == {
        "case_id": "case_one",
        "size_bytes": 2,
    }
    assert repository.get_report("case_one") == b"{}"
    assert repository.get_report("current") is None
    assert repository.get_report("latest") is None


@pytest.mark.parametrize(
    "reports",
    [
        [
            {"case_id": "duplicate", "report": "one.json"},
            {"case_id": "duplicate", "report": "two.json"},
        ],
        [
            {"case_id": "one", "report": "same.json"},
            {"case_id": "two", "report": "same.json"},
        ],
        [{"case_id": "../escape", "report": "one.json"}],
    ],
)
def test_repository_rejects_invalid_or_duplicate_mapping(
    tmp_path: Path,
    reports: list[dict[str, str]],
) -> None:
    _write_catalog(tmp_path, reports)
    with pytest.raises(ReportRepositoryError):
        FilesystemReportRepository(tmp_path).list_reports()


@pytest.mark.parametrize("unsafe_path", ["../outside.json", "/tmp/outside.json"])
def test_repository_rejects_path_traversal(tmp_path: Path, unsafe_path: str) -> None:
    _write_catalog(tmp_path, [{"case_id": "case_one", "report": unsafe_path}])
    with pytest.raises(ReportRepositoryError):
        FilesystemReportRepository(tmp_path).list_reports()


def test_repository_rejects_symlinked_report(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-report.json"
    outside.write_bytes(b"{}")
    (tmp_path / "linked.json").symlink_to(outside)
    _write_catalog(tmp_path, [{"case_id": "case_one", "report": "linked.json"}])
    with pytest.raises(ReportRepositoryError, match="symlink"):
        FilesystemReportRepository(tmp_path).get_report("case_one")


def test_repository_enforces_report_count_and_file_size(tmp_path: Path) -> None:
    (tmp_path / "one.json").write_bytes(b"12345")
    (tmp_path / "two.json").write_bytes(b"{}")
    _write_catalog(
        tmp_path,
        [
            {"case_id": "one", "report": "one.json"},
            {"case_id": "two", "report": "two.json"},
        ],
    )
    with pytest.raises(ReportRepositoryError, match="entries"):
        FilesystemReportRepository(tmp_path, max_report_count=1).list_reports()
    with pytest.raises(ReportRepositoryError, match="exceeds"):
        FilesystemReportRepository(tmp_path, max_report_bytes=4).list_reports()


def test_repository_missing_root_or_catalog_is_empty(tmp_path: Path) -> None:
    assert FilesystemReportRepository(tmp_path / "missing").list_reports() == ()
    assert FilesystemReportRepository(tmp_path).list_reports() == ()
