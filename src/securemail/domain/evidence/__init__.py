"""Evidence models. `EvidenceState` is defined only in `run.py`."""

from securemail.domain.evidence.certificate import (
    CertificateEvidence,
    CertificateRole,
    CertificateValidation,
    ReferenceIdentitySource,
    RevocationStatus,
)
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
from securemail.domain.evidence.handshake import (
    CipherSuiteEvidence,
    HandshakeMessage,
    HandshakeMessageKind,
    HandshakeSignatureEvidence,
    HandshakeVisibility,
    KeyExchangeEvidence,
    TlsHandshake,
    TlsVersionEvidence,
    VersionSource,
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
    EventSource,
    ExplicitUpgrade,
    ImplicitTls,
    MailProtocol,
    PayloadEvidence,
    PortHint,
    ProtocolEvent,
    SessionEventKind,
    UpgradeState,
)

EvidenceDocument.model_rebuild(
    _types_namespace={
        "Flow": Flow,
        "EmailSession": EmailSession,
        "TlsHandshake": TlsHandshake,
        "CertificateEvidence": CertificateEvidence,
    }
)

__all__ = [
    "NORMALIZATION_SCHEMA_VERSION",
    "AnalysisRun",
    "ByteRange",
    "CapturePreflight",
    "CertificateEvidence",
    "CertificateRole",
    "CertificateValidation",
    "ReferenceIdentitySource",
    "RevocationStatus",
    "CipherSuiteEvidence",
    "EmailSession",
    "EventSource",
    "EvidenceDocument",
    "EvidenceState",
    "ExplicitUpgrade",
    "ImplicitTls",
    "Flow",
    "FlowEndpoint",
    "HandshakeMessage",
    "HandshakeMessageKind",
    "HandshakeSignatureEvidence",
    "HandshakeVisibility",
    "KeyExchangeEvidence",
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
    "TlsHandshake",
    "TlsVersionEvidence",
    "UpgradeState",
    "VersionSource",
    "classify_reconstruction",
]
