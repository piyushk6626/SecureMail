"""Versioned integer priority score. Named components are part of the contract."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from securemail.domain.evidence.run import EvidenceState
from securemail.domain.findings.finding import FindingSeverity

SCORING_SCHEMA_VERSION: Literal["securemail.scoring/v1"] = "securemail.scoring/v1"

SEVERITY_POINTS: dict[FindingSeverity, int] = {
    FindingSeverity.HIGH: 50,
    FindingSeverity.MEDIUM: 30,
    FindingSeverity.LOW: 15,
    FindingSeverity.INFORMATIONAL: 0,
}
CONFIDENCE_POINTS: dict[EvidenceState, int] = {
    EvidenceState.VERIFIED: 20,
    EvidenceState.OBSERVED: 16,
    EvidenceState.INFERRED: 12,
    EvidenceState.INCOMPLETE: 6,
    EvidenceState.CONFLICTING: 3,
    EvidenceState.INDETERMINATE: 2,
    EvidenceState.NOT_OBSERVABLE: 0,
}
RECURRENCE_STEP = 2
RECURRENCE_CAP = 10


class ExposureClass(StrEnum):
    PUBLIC = "public"
    PARTNER = "partner"
    INTERNAL = "internal"
    ISOLATED = "isolated"
    UNKNOWN = "unknown"


class AssetCriticality(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class BlastRadius(StrEnum):
    ORGANIZATION = "organization"
    MULTI_ASSET = "multi_asset"
    SINGLE_ENDPOINT = "single_endpoint"
    UNKNOWN = "unknown"


EXPOSURE_POINTS: dict[ExposureClass, int] = {
    ExposureClass.PUBLIC: 10,
    ExposureClass.PARTNER: 8,
    ExposureClass.INTERNAL: 5,
    ExposureClass.ISOLATED: 2,
    ExposureClass.UNKNOWN: 4,
}
CRITICALITY_POINTS: dict[AssetCriticality, int] = {
    AssetCriticality.CRITICAL: 5,
    AssetCriticality.HIGH: 4,
    AssetCriticality.MEDIUM: 3,
    AssetCriticality.LOW: 1,
    AssetCriticality.UNKNOWN: 2,
}
BLAST_RADIUS_POINTS: dict[BlastRadius, int] = {
    BlastRadius.ORGANIZATION: 5,
    BlastRadius.MULTI_ASSET: 3,
    BlastRadius.SINGLE_ENDPOINT: 1,
    BlastRadius.UNKNOWN: 1,
}


class AssetContext(BaseModel):
    """Optional inventory labels for an endpoint. Missing labels serialize as unknown."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint: str = Field(min_length=1, max_length=300)
    exposure: ExposureClass = ExposureClass.UNKNOWN
    asset_criticality: AssetCriticality = AssetCriticality.UNKNOWN
    blast_radius: BlastRadius = BlastRadius.UNKNOWN


class ScoreInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    severity: FindingSeverity
    basis_state: EvidenceState
    exposure: ExposureClass = ExposureClass.UNKNOWN
    unique_occurrences: int = Field(default=1, ge=1, le=1_000_000)
    asset_criticality: AssetCriticality = AssetCriticality.UNKNOWN
    blast_radius: BlastRadius = BlastRadius.UNKNOWN


class ScoreComponents(BaseModel):
    """Hand-computable addends. Sum is the published score (naturally ≤ 100)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    severity: int = Field(ge=0, le=50)
    confidence: int = Field(ge=0, le=20)
    exposure: int = Field(ge=0, le=10)
    recurrence: int = Field(ge=0, le=10)
    asset_criticality: int = Field(ge=0, le=5)
    blast_radius: int = Field(ge=0, le=5)


class ScoreVector(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scoring_schema_version: Literal["securemail.scoring/v1"] = SCORING_SCHEMA_VERSION
    score: int = Field(ge=0, le=100)
    components: ScoreComponents


def recurrence_points(unique_occurrences: int) -> int:
    if unique_occurrences < 1:
        raise ValueError("unique_occurrences must be at least 1")
    return min(RECURRENCE_CAP, RECURRENCE_STEP * (unique_occurrences - 1))


def compute_score(inputs: ScoreInput) -> ScoreVector:
    """Pure v1 priority arithmetic. Unknown inventory labels are explicit addends."""

    components = ScoreComponents(
        severity=SEVERITY_POINTS[inputs.severity],
        confidence=CONFIDENCE_POINTS[inputs.basis_state],
        exposure=EXPOSURE_POINTS[inputs.exposure],
        recurrence=recurrence_points(inputs.unique_occurrences),
        asset_criticality=CRITICALITY_POINTS[inputs.asset_criticality],
        blast_radius=BLAST_RADIUS_POINTS[inputs.blast_radius],
    )
    total = (
        components.severity
        + components.confidence
        + components.exposure
        + components.recurrence
        + components.asset_criticality
        + components.blast_radius
    )
    return ScoreVector(score=min(100, total), components=components)
