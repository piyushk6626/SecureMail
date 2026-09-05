"""Capture-analysis job models."""

from securemail.domain.jobs.models import (
    MAX_CAPTURE_BYTES,
    MAX_DATA_ROOT_BYTES,
    MAX_HTML_BYTES,
    MAX_JOB_COUNT,
    MAX_ML_WINDOWS,
    MAX_ORIGINAL_FILENAME_CHARS,
    MAX_PDF_BYTES,
    AnalysisJob,
    AnalysisStage,
    AnalysisStatus,
    ArtifactAvailability,
)

__all__ = [
    "MAX_CAPTURE_BYTES",
    "MAX_DATA_ROOT_BYTES",
    "MAX_HTML_BYTES",
    "MAX_JOB_COUNT",
    "MAX_ML_WINDOWS",
    "MAX_ORIGINAL_FILENAME_CHARS",
    "MAX_PDF_BYTES",
    "AnalysisJob",
    "AnalysisStage",
    "AnalysisStatus",
    "ArtifactAvailability",
]
