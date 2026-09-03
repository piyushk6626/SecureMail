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
from securemail.domain.evidence.session import (
    EmailSession,
    MailProtocol,
    PayloadEvidence,
    PortHint,
    ProtocolEvent,
    SessionEventKind,
)

EvidenceDocument.model_rebuild(_types_namespace={"Flow": Flow, "EmailSession": EmailSession})

__all__ = [
    "NORMALIZATION_SCHEMA_VERSION",
    "AnalysisRun",
    "ByteRange",
    "CapturePreflight",
    "EmailSession",
    "EvidenceDocument",
    "EvidenceState",
    "Flow",
    "FlowEndpoint",
    "MailProtocol",
    "ObservedCondition",
    "PayloadEvidence",
    "PortHint",
    "ProtocolEvent",
    "ReconstructionFacts",
    "ReconstructionQuality",
    "ReconstructionReasonCode",
    "ReconstructionVerdict",
    "SessionEventKind",
    "StreamDirection",
    "classify_reconstruction",
]
