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
    EVIDENCE_DOCUMENT_SCHEMA_VERSION,
    NORMALIZATION_SCHEMA_VERSION,
    AnalysisRun,
    CapturePreflight,
    EvidenceDocument,
    EvidenceState,
    PolicyProfile,
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
from securemail.domain.findings.finding import Finding
from securemail.domain.findings.posture import PolicyCheck, PostureAssessment

EvidenceDocument.model_rebuild(
    _types_namespace={
        "Flow": Flow,
        "EmailSession": EmailSession,
        "TlsHandshake": TlsHandshake,
        "CertificateEvidence": CertificateEvidence,
        "Finding": Finding,
        "PolicyCheck": PolicyCheck,
        "PostureAssessment": PostureAssessment,
    }
)

__all__ = [
    "EVIDENCE_DOCUMENT_SCHEMA_VERSION",
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
    "Finding",
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
    "PolicyCheck",
    "PolicyProfile",
    "PortHint",
    "PostureAssessment",
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
