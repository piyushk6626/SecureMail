"""Ports for advisory anomaly scoring. Domain types only; no sklearn."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from securemail.domain.ml.models import EndpointWindow, WindowScore


class MlDependencyError(Exception):
    """Raised when the optional `ml` extra is required but missing."""


@runtime_checkable
class AnomalyScorer(Protocol):
    """Score endpoint-windows using only past history for each window."""

    @property
    def name(self) -> str: ...

    @property
    def model_digest(self) -> str: ...

    def score_windows(self, windows: Sequence[EndpointWindow]) -> list[WindowScore]:
        """Return one score per input window, aligned by endpoint_id and day_index."""
        ...
