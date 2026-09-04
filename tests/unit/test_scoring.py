"""Exact v1 scoring arithmetic. Components are the regression contract."""

from __future__ import annotations

import pytest

from securemail.domain.evidence.run import EvidenceState
from securemail.domain.findings.finding import FindingSeverity
from securemail.domain.findings.scoring import (
    SCORING_SCHEMA_VERSION,
    AssetCriticality,
    BlastRadius,
    ExposureClass,
    ScoreInput,
    compute_score,
    recurrence_points,
)


@pytest.mark.parametrize(
    ("severity", "points"),
    [
        (FindingSeverity.HIGH, 50),
        (FindingSeverity.MEDIUM, 30),
        (FindingSeverity.LOW, 15),
        (FindingSeverity.INFORMATIONAL, 0),
    ],
)
def test_severity_table(severity: FindingSeverity, points: int) -> None:
    vector = compute_score(ScoreInput(severity=severity, basis_state=EvidenceState.NOT_OBSERVABLE))
    assert vector.components.severity == points


@pytest.mark.parametrize(
    ("state", "points"),
    [
        (EvidenceState.VERIFIED, 20),
        (EvidenceState.OBSERVED, 16),
        (EvidenceState.INFERRED, 12),
        (EvidenceState.INCOMPLETE, 6),
        (EvidenceState.CONFLICTING, 3),
        (EvidenceState.INDETERMINATE, 2),
        (EvidenceState.NOT_OBSERVABLE, 0),
    ],
)
def test_confidence_table(state: EvidenceState, points: int) -> None:
    vector = compute_score(ScoreInput(severity=FindingSeverity.INFORMATIONAL, basis_state=state))
    assert vector.components.confidence == points


@pytest.mark.parametrize(
    ("exposure", "points"),
    [
        (ExposureClass.PUBLIC, 10),
        (ExposureClass.PARTNER, 8),
        (ExposureClass.INTERNAL, 5),
        (ExposureClass.ISOLATED, 2),
        (ExposureClass.UNKNOWN, 4),
    ],
)
def test_exposure_table(exposure: ExposureClass, points: int) -> None:
    vector = compute_score(
        ScoreInput(
            severity=FindingSeverity.INFORMATIONAL,
            basis_state=EvidenceState.NOT_OBSERVABLE,
            exposure=exposure,
        )
    )
    assert vector.components.exposure == points


@pytest.mark.parametrize(
    ("criticality", "points"),
    [
        (AssetCriticality.CRITICAL, 5),
        (AssetCriticality.HIGH, 4),
        (AssetCriticality.MEDIUM, 3),
        (AssetCriticality.LOW, 1),
        (AssetCriticality.UNKNOWN, 2),
    ],
)
def test_criticality_table(criticality: AssetCriticality, points: int) -> None:
    vector = compute_score(
        ScoreInput(
            severity=FindingSeverity.INFORMATIONAL,
            basis_state=EvidenceState.NOT_OBSERVABLE,
            asset_criticality=criticality,
        )
    )
    assert vector.components.asset_criticality == points


@pytest.mark.parametrize(
    ("blast", "points"),
    [
        (BlastRadius.ORGANIZATION, 5),
        (BlastRadius.MULTI_ASSET, 3),
        (BlastRadius.SINGLE_ENDPOINT, 1),
        (BlastRadius.UNKNOWN, 1),
    ],
)
def test_blast_radius_table(blast: BlastRadius, points: int) -> None:
    vector = compute_score(
        ScoreInput(
            severity=FindingSeverity.INFORMATIONAL,
            basis_state=EvidenceState.NOT_OBSERVABLE,
            blast_radius=blast,
        )
    )
    assert vector.components.blast_radius == points


@pytest.mark.parametrize(
    ("occurrences", "points"),
    [(1, 0), (2, 2), (3, 4), (6, 10), (99, 10)],
)
def test_recurrence_cap(occurrences: int, points: int) -> None:
    assert recurrence_points(occurrences) == points
    vector = compute_score(
        ScoreInput(
            severity=FindingSeverity.INFORMATIONAL,
            basis_state=EvidenceState.NOT_OBSERVABLE,
            unique_occurrences=occurrences,
        )
    )
    assert vector.components.recurrence == points


def test_unknown_inventory_defaults_are_explicit() -> None:
    vector = compute_score(
        ScoreInput(severity=FindingSeverity.LOW, basis_state=EvidenceState.OBSERVED)
    )
    assert vector.components.exposure == 4
    assert vector.components.asset_criticality == 2
    assert vector.components.blast_radius == 1
    assert vector.score == 15 + 16 + 4 + 0 + 2 + 1


def test_hand_computed_high_verified_public_critical() -> None:
    vector = compute_score(
        ScoreInput(
            severity=FindingSeverity.HIGH,
            basis_state=EvidenceState.VERIFIED,
            exposure=ExposureClass.PUBLIC,
            unique_occurrences=1,
            asset_criticality=AssetCriticality.CRITICAL,
            blast_radius=BlastRadius.ORGANIZATION,
        )
    )
    assert vector.scoring_schema_version == SCORING_SCHEMA_VERSION
    assert vector.components.severity == 50
    assert vector.components.confidence == 20
    assert vector.components.exposure == 10
    assert vector.components.recurrence == 0
    assert vector.components.asset_criticality == 5
    assert vector.components.blast_radius == 5
    assert vector.score == 90


def test_natural_cap_is_100() -> None:
    vector = compute_score(
        ScoreInput(
            severity=FindingSeverity.HIGH,
            basis_state=EvidenceState.VERIFIED,
            exposure=ExposureClass.PUBLIC,
            unique_occurrences=6,
            asset_criticality=AssetCriticality.CRITICAL,
            blast_radius=BlastRadius.ORGANIZATION,
        )
    )
    assert vector.score == 100


def test_score_is_monotonic_in_severity() -> None:
    low = compute_score(
        ScoreInput(severity=FindingSeverity.LOW, basis_state=EvidenceState.OBSERVED)
    )
    medium = compute_score(
        ScoreInput(severity=FindingSeverity.MEDIUM, basis_state=EvidenceState.OBSERVED)
    )
    high = compute_score(
        ScoreInput(severity=FindingSeverity.HIGH, basis_state=EvidenceState.OBSERVED)
    )
    assert low.score < medium.score < high.score
