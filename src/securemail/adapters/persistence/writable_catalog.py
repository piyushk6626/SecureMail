"""Atomic catalog publication for canonical reports."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from pydantic import ValidationError

from securemail.adapters.persistence.report_repository import (
    CATALOG_FILENAME,
    CATALOG_SCHEMA_VERSION,
    DEFAULT_MAX_REPORT_COUNT,
    FilesystemReportRepository,
)
from securemail.ports.persistence import MAX_REPORT_BYTES, ReportRepositoryError

_CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")


class FilesystemCatalogPublisher:
    """Write ``{case_id}.report.json`` and update ``catalog.json`` atomically."""

    def __init__(
        self,
        root: Path,
        *,
        max_report_bytes: int = MAX_REPORT_BYTES,
        max_report_count: int = DEFAULT_MAX_REPORT_COUNT,
    ) -> None:
        self._root = root.expanduser().absolute()
        self._max_report_bytes = max_report_bytes
        self._max_report_count = max_report_count
        self._reader = FilesystemReportRepository(
            self._root,
            max_report_bytes=max_report_bytes,
            max_report_count=max_report_count,
        )

    def publish_report(self, case_id: str, canonical_bytes: bytes) -> None:
        if _CASE_ID_PATTERN.fullmatch(case_id) is None:
            raise ReportRepositoryError("invalid case ID")
        if len(canonical_bytes) > self._max_report_bytes:
            raise ReportRepositoryError(f"report exceeds {self._max_report_bytes} bytes")
        self._root.mkdir(parents=True, exist_ok=True)
        if self._root.is_symlink() or not self._root.is_dir():
            raise ReportRepositoryError("report root must be a non-symlink directory")
        filename = f"{case_id}.report.json"
        report_path = self._root / filename
        tmp_report = self._root / f".{filename}.tmp"
        tmp_report.write_bytes(canonical_bytes)
        os.replace(tmp_report, report_path)

        catalog_path = self._root / CATALOG_FILENAME
        items = self._load_items(catalog_path)
        items = [item for item in items if item["case_id"] != case_id]
        items.append({"case_id": case_id, "report": filename})
        items.sort(key=lambda item: str(item["case_id"]))
        if len(items) > self._max_report_count:
            raise ReportRepositoryError(f"report catalog exceeds {self._max_report_count} entries")
        payload = {
            "schema_version": CATALOG_SCHEMA_VERSION,
            "reports": items,
        }
        raw = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        tmp_catalog = self._root / f".{CATALOG_FILENAME}.tmp"
        tmp_catalog.write_text(raw, encoding="utf-8")
        os.replace(tmp_catalog, catalog_path)

    def _load_items(self, catalog_path: Path) -> list[dict[str, str]]:
        if not catalog_path.exists():
            return []
        try:
            payload = json.loads(catalog_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReportRepositoryError("report catalog is not valid JSON") from exc
        if not isinstance(payload, dict) or payload.get("schema_version") != CATALOG_SCHEMA_VERSION:
            raise ReportRepositoryError("unsupported report catalog schema version")
        reports = payload.get("reports")
        if not isinstance(reports, list):
            raise ReportRepositoryError("report catalog is not valid JSON")
        items: list[dict[str, str]] = []
        try:
            for item in reports:
                if not isinstance(item, dict):
                    raise ReportRepositoryError("report catalog is not valid JSON")
                case_id = item["case_id"]
                report = item["report"]
                if not isinstance(case_id, str) or not isinstance(report, str):
                    raise ReportRepositoryError("report catalog is not valid JSON")
                items.append({"case_id": case_id, "report": report})
        except (KeyError, ValidationError) as exc:
            raise ReportRepositoryError("report catalog is not valid JSON") from exc
        return items
