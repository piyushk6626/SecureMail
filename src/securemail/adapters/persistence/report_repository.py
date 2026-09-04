"""Manifest-backed, read-only filesystem repository for canonical reports."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path, PurePath

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from securemail.ports.persistence import (
    MAX_REPORT_BYTES,
    ReportCatalogEntry,
    ReportRepositoryError,
)

CATALOG_FILENAME = "catalog.json"
CATALOG_SCHEMA_VERSION = "securemail.report-catalog/v1"
MAX_CATALOG_BYTES = 1024 * 1024
DEFAULT_MAX_REPORT_COUNT = 256
_CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")


class _CatalogItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(min_length=1, max_length=160)
    report: str = Field(min_length=1, max_length=512)


class _Catalog(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    reports: list[_CatalogItem]


class FilesystemReportRepository:
    """Read reports explicitly named by ``catalog.json`` beneath one root."""

    def __init__(
        self,
        root: Path,
        *,
        max_report_bytes: int = MAX_REPORT_BYTES,
        max_report_count: int = DEFAULT_MAX_REPORT_COUNT,
    ) -> None:
        if max_report_bytes < 1:
            raise ValueError("max_report_bytes must be positive")
        if max_report_count < 1:
            raise ValueError("max_report_count must be positive")
        self._root = root.expanduser().absolute()
        self._max_report_bytes = max_report_bytes
        self._max_report_count = max_report_count

    def list_reports(self) -> tuple[ReportCatalogEntry, ...]:
        paths = self._load_catalog_paths()
        entries = [
            ReportCatalogEntry(case_id=case_id, size_bytes=self._safe_size(path))
            for case_id, path in paths.items()
        ]
        return tuple(sorted(entries, key=lambda item: item.case_id))

    def get_report(self, case_id: str) -> bytes | None:
        paths = self._load_catalog_paths()
        path = paths.get(case_id)
        if path is None:
            return None
        return self._read_bounded_file(path, self._max_report_bytes, "report")

    def _load_catalog_paths(self) -> dict[str, Path]:
        root = self._validated_root()
        if root is None:
            return {}
        catalog_path = root / CATALOG_FILENAME
        if not catalog_path.exists():
            return {}
        raw = self._read_bounded_file(catalog_path, MAX_CATALOG_BYTES, "report catalog")
        try:
            payload = json.loads(raw.decode("utf-8"))
            catalog = _Catalog.model_validate(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
            raise ReportRepositoryError("report catalog is not valid JSON") from exc
        if catalog.schema_version != CATALOG_SCHEMA_VERSION:
            raise ReportRepositoryError("unsupported report catalog schema version")
        if len(catalog.reports) > self._max_report_count:
            raise ReportRepositoryError(f"report catalog exceeds {self._max_report_count} entries")

        paths: dict[str, Path] = {}
        used_paths: set[Path] = set()
        for item in catalog.reports:
            if _CASE_ID_PATTERN.fullmatch(item.case_id) is None:
                raise ReportRepositoryError("report catalog contains an invalid case ID")
            if item.case_id in paths:
                raise ReportRepositoryError(f"duplicate case ID in report catalog: {item.case_id}")
            report_path = self._validated_report_path(root, item.report)
            if report_path in used_paths:
                raise ReportRepositoryError("report catalog maps multiple case IDs to one report")
            paths[item.case_id] = report_path
            used_paths.add(report_path)
        return paths

    def _validated_root(self) -> Path | None:
        if not self._root.exists():
            return None
        if self._root.is_symlink() or not self._root.is_dir():
            raise ReportRepositoryError("report root must be a non-symlink directory")
        return self._root

    def _validated_report_path(self, root: Path, raw_path: str) -> Path:
        relative = PurePath(raw_path)
        if relative.is_absolute() or ".." in relative.parts or "." in relative.parts:
            raise ReportRepositoryError("report catalog path must remain beneath report root")
        if not relative.parts or relative.suffix.lower() != ".json":
            raise ReportRepositoryError("report catalog entries must name JSON files")
        candidate = root.joinpath(*relative.parts)
        if candidate == root / CATALOG_FILENAME:
            raise ReportRepositoryError("report catalog cannot reference itself")
        current = root
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                raise ReportRepositoryError("symlinks are not allowed in report catalog paths")
        try:
            candidate.resolve(strict=False).relative_to(root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise ReportRepositoryError("report catalog path escapes report root") from exc
        return candidate

    def _safe_size(self, path: Path) -> int:
        try:
            file_stat = path.stat(follow_symlinks=False)
        except FileNotFoundError as exc:
            raise ReportRepositoryError("cataloged report file is missing") from exc
        except OSError as exc:
            raise ReportRepositoryError("cataloged report file cannot be inspected") from exc
        if not stat.S_ISREG(file_stat.st_mode):
            raise ReportRepositoryError("cataloged report must be a regular file")
        if file_stat.st_size > self._max_report_bytes:
            raise ReportRepositoryError(f"cataloged report exceeds {self._max_report_bytes} bytes")
        return file_stat.st_size

    @staticmethod
    def _read_bounded_file(path: Path, limit: int, label: str) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ReportRepositoryError(f"{label} cannot be opened safely") from exc
        try:
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise ReportRepositoryError(f"{label} must be a regular file")
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
        except OSError as exc:
            raise ReportRepositoryError(f"{label} cannot be read") from exc
        finally:
            os.close(descriptor)
        if len(payload) > limit:
            raise ReportRepositoryError(f"{label} exceeds {limit} bytes")
        return payload
