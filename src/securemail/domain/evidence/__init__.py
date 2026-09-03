"""Evidence models. `EvidenceState` is defined only in `run.py`."""

from securemail.domain.evidence.flow import (
    ByteRange,
    Flow,
    FlowEndpoint,
    ObservedCondition,
    ReconstructionFacts,
    ReconstructionQuality,
    ReconstructionReasonCode,
    ReconstructionVerdict,
    StreamDirection,
    classify_reconstruction,
)
from securemail.domain.evidence.run import (
    NORMALIZATION_SCHEMA_VERSION,
    AnalysisRun,
    CapturePreflight,
    EvidenceDocument,
    EvidenceState,
)

EvidenceDocument.model_rebuild(_types_namespace={"Flow": Flow})

__all__ = [
    "NORMALIZATION_SCHEMA_VERSION",
    "AnalysisRun",
    "ByteRange",
    "CapturePreflight",
    "EvidenceDocument",
    "EvidenceState",
    "Flow",
    "FlowEndpoint",
    "ObservedCondition",
    "ReconstructionFacts",
    "ReconstructionQuality",
    "ReconstructionReasonCode",
    "ReconstructionVerdict",
    "StreamDirection",
    "classify_reconstruction",
]
