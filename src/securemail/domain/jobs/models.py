"""Durable capture-analysis job records. Pure models; no I/O."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_serializer

_SHA256 = r"^[0-9a-f]{64}$"
_ID = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$"

MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_JOB_COUNT = 64
MAX_DATA_ROOT_BYTES = 2 * 1024 * 1024 * 1024
MAX_HTML_BYTES = 16 * 1024 * 1024
MAX_PDF_BYTES = 32 * 1024 * 1024
MAX_ML_WINDOWS = 512
MAX_ORIGINAL_FILENAME_CHARS = 255


class AnalysisStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AnalysisStage(StrEnum):
    INTAKE = "intake"
    DETERMINISTIC_ANALYSIS = "deterministic_analysis"
    POLICY_SCORING = "policy_scoring"
    ML_ADVISORY = "ml_advisory"
    REPORT_RENDERING = "report_rendering"
    PUBLICATION = "publication"


class ArtifactAvailability(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        serialize_by_alias=True,
    )

    canonical: bool = Field(default=False, alias="json")
    html: bool = False
    pdf: bool = False


class AnalysisJob(BaseModel):
    """One capture analysis run. Filesystem paths never appear on this model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str = Field(pattern=_ID)
    case_id: str = Field(pattern=_ID)
    status: AnalysisStatus
    stage: AnalysisStage
    capture_sha256: str | None = Field(default=None, pattern=_SHA256)
    original_filename: str = Field(min_length=1, max_length=MAX_ORIGINAL_FILENAME_CHARS)
    capture_format: str = Field(pattern=r"^pcap(ng)?$")
    policy_profile: str = Field(min_length=1, max_length=64)
    expected_hostname: str | None = Field(default=None, max_length=253)
    created_at: datetime
    updated_at: datetime
    error_message: str | None = Field(default=None, max_length=1000)
    artifacts: ArtifactAvailability = Field(default_factory=ArtifactAvailability)
    cancel_requested: bool = False

    @field_serializer("created_at", "updated_at")
    def _serialize_datetime(self, value: datetime) -> str:
        aware = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return aware.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

    @property
    def is_terminal(self) -> bool:
        return self.status in {
            AnalysisStatus.COMPLETED,
            AnalysisStatus.FAILED,
            AnalysisStatus.CANCELLED,
        }
