"""Append-only JSONL store for derived ML endpoint-windows."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from securemail.domain.jobs.models import MAX_ML_WINDOWS
from securemail.domain.ml.models import EndpointWindow
from securemail.ports.ml_history import MlHistoryError


class FilesystemMlHistoryStore:
    def __init__(self, root: Path, *, max_windows: int = MAX_ML_WINDOWS) -> None:
        if max_windows < 1:
            raise ValueError("max_windows must be positive")
        self._root = root.expanduser().absolute()
        self._max_windows = max_windows

    def load_windows(self) -> list[EndpointWindow]:
        path = self._path()
        if not path.exists():
            return []
        if path.is_symlink() or not path.is_file():
            raise MlHistoryError("ML history must be a regular file")
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise MlHistoryError("ML history cannot be read") from exc
        windows: list[EndpointWindow] = []
        for line in lines:
            if not line.strip():
                continue
            try:
                windows.append(EndpointWindow.model_validate(json.loads(line)))
            except (json.JSONDecodeError, ValidationError) as exc:
                raise MlHistoryError("ML history contains an invalid window") from exc
        windows.sort(key=lambda item: (item.day_index, item.endpoint_id))
        return windows[-self._max_windows :]

    def append_windows(self, windows: Sequence[EndpointWindow]) -> list[EndpointWindow]:
        retained = self.load_windows()
        retained.extend(windows)
        retained = retained[-self._max_windows :]
        self._root.mkdir(parents=True, exist_ok=True)
        directory = self._root / "ml_history"
        directory.mkdir(mode=0o700, exist_ok=True)
        path = self._path()
        tmp = directory / ".windows.jsonl.tmp"
        payload = "".join(item.model_dump_json() + "\n" for item in retained)
        tmp.write_text(payload, encoding="utf-8")
        tmp.replace(path)
        return retained

    def _path(self) -> Path:
        return self._root / "ml_history" / "windows.jsonl"
