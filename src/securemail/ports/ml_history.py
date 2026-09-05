"""Bounded local ML endpoint-window history."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from securemail.domain.ml.models import EndpointWindow


class MlHistoryError(Exception):
    """Raised when the local window history cannot be read or written."""


@runtime_checkable
class MlHistoryStore(Protocol):
    """Persist derived endpoint-windows only. No raw IPs as extra fields."""

    def load_windows(self) -> list[EndpointWindow]:
        """Return stored windows in day-index order, bounded by the contract cap."""

    def append_windows(self, windows: Sequence[EndpointWindow]) -> list[EndpointWindow]:
        """Append new windows, drop oldest past the cap, return the retained list."""
