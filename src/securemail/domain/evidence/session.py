"""Canonical email-session identification and STARTTLS/STLS assessments."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from securemail.domain.evidence.flow import StreamDirection
from securemail.domain.evidence.run import EvidenceState


class MailProtocol(StrEnum):
    """Resolved application protocol. Distinct from `port_hint`."""

    SMTP = "smtp"
    IMAP = "imap"
    POP3 = "pop3"


class PortHint(StrEnum):
    """Well-known-port inference only. Never used as protocol proof."""

    SMTP = "smtp"
    IMAP = "imap"
    POP3 = "pop3"
    NONE = "none"


class PayloadEvidence(StrEnum):
    """Protocol identity derived from payload / analyzer events, not ports."""

    SMTP = "smtp"
    IMAP = "imap"
    POP3 = "pop3"
    INDETERMINATE = "indeterminate"
    NONE = "none"


class SessionEventKind(StrEnum):
    """Bounded protocol-event kinds recorded on an `EmailSession`."""

    REQUEST = "request"
    REPLY = "reply"
    CAPABILITY = "capability"
    STARTTLS = "starttls"
    CONFIRMATION = "confirmation"
    AMBIGUOUS_BANNER = "ambiguous_banner"
    UNEXPECTED = "unexpected"


class EventSource(StrEnum):
    """Analyzer that produced a protocol observation."""

    ZEEK = "zeek"
    TSHARK = "tshark"
    SSL = "ssl"


class UpgradeState(StrEnum):
    """Terminal STARTTLS/STLS state-machine outcome."""

    ADVERTISED = "advertised"
    REQUESTED = "requested"
    ACCEPTED = "accepted"
    TLS_ESTABLISHED = "tls_established"
    PLAINTEXT_FALLBACK = "plaintext_fallback"
    VIOLATION = "violation"


class ProtocolEvent(BaseModel):
    """One redacted, length-bounded command/response/capability observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    direction: StreamDirection
    kind: SessionEventKind
    command: str | None = None
    argument: str | None = None
    reply_code: int | None = Field(default=None, ge=0)
    text: str | None = None
    frame_number: int | None = Field(default=None, ge=1)
    source: EventSource | None = None
    tag: str | None = None


class ExplicitUpgrade(BaseModel):
    """STARTTLS/STLS assessment. `downgrade_consistent` is never proof of attack."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: UpgradeState | None = None
    evidence_state: EvidenceState
    evidence_frames: list[int] = Field(default_factory=list)
    downgrade_consistent: bool = False


class ImplicitTls(BaseModel):
    """Implicit-TLS correlation. Port alone never sets `correlated_protocol`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    correlated_protocol: MailProtocol | None = None
    evidence_state: EvidenceState
    source: Literal["alpn", "none"] | None = None
    evidence_frames: list[int] = Field(default_factory=list)


class EmailSession(BaseModel):
    """Protocol-tagged session with independent port and payload fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    uid: str
    protocol: MailProtocol | None = None
    port_hint: PortHint
    payload_evidence: PayloadEvidence
    evidence_state: EvidenceState
    identification_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    corroboration: Literal["zeek", "zeek+tshark"] = "zeek"
    events: list[ProtocolEvent] = Field(default_factory=list)
    explicit_upgrade: ExplicitUpgrade | None = None
    implicit_tls: ImplicitTls | None = None


def _rebuild_evidence_document() -> None:
    """Resolve `EmailSession` on `EvidenceDocument` without an import cycle."""

    from securemail.domain.evidence.certificate import CertificateEvidence
    from securemail.domain.evidence.flow import Flow
    from securemail.domain.evidence.handshake import TlsHandshake
    from securemail.domain.evidence.run import EvidenceDocument
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


_rebuild_evidence_document()
