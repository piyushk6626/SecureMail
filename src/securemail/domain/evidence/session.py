"""Canonical email-session identification (Step 2)."""

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


class ProtocolEvent(BaseModel):
    """One redacted, length-bounded command/response/capability observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    direction: StreamDirection
    kind: SessionEventKind
    command: str | None = None
    argument: str | None = None
    reply_code: int | None = Field(default=None, ge=0)
    text: str | None = None


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


def _rebuild_evidence_document() -> None:
    """Resolve `EmailSession` on `EvidenceDocument` without an import cycle."""

    from securemail.domain.evidence.flow import Flow
    from securemail.domain.evidence.run import EvidenceDocument

    EvidenceDocument.model_rebuild(_types_namespace={"Flow": Flow, "EmailSession": EmailSession})


_rebuild_evidence_document()
