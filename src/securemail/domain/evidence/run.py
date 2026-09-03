"""Canonical run identity and the shared evidence-state vocabulary (schema v0)."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

NORMALIZATION_SCHEMA_VERSION: Literal["v0"] = "v0"


class EvidenceState(StrEnum):
    """Mandatory visibility/confidence state for every applicable evidence field."""

    OBSERVED = "observed"
    VERIFIED = "verified"
    INFERRED = "inferred"
    INCOMPLETE = "incomplete"
    CONFLICTING = "conflicting"
    NOT_OBSERVABLE = "not_observable"
    INDETERMINATE = "indeterminate"


class AnalysisRun(BaseModel):
    """Identity record for one analysis of one capture."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    analyzer_bundle_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalization_schema_version: Literal["v0"]
    configuration_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_pack_version: str | None = None
    trust_store_digest: str | None = None


class EvidenceDocument(BaseModel):
    """v0 canonical JSON envelope produced by `securemail analyze`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["v0"] = "v0"
    run_identity: AnalysisRun
