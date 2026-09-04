"""Canonical TLS handshake evidence (v1 envelope, Step 4)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from securemail.domain.evidence.flow import StreamDirection
from securemail.domain.evidence.run import EvidenceState


class HandshakeVisibility(StrEnum):
    """How much of the handshake is passively visible."""

    FULL = "full"
    PARTIAL = "partial"
    NOT_OBSERVABLE = "not_observable"


class VersionSource(StrEnum):
    """Where the selected TLS version was taken from. Never ClientHello offers."""

    SUPPORTED_VERSIONS = "supported_versions"
    LEGACY_RECORD = "legacy_record"


class HandshakeMessageKind(StrEnum):
    """Handshake/record kinds reconstructed from Zeek `ssl_history` letters."""

    DIRECTION_FLIP = "direction_flip"
    HELLO_REQUEST = "hello_request"
    CLIENT_HELLO = "client_hello"
    SERVER_HELLO = "server_hello"
    HELLO_RETRY_REQUEST = "hello_retry_request"
    HELLO_VERIFY_REQUEST = "hello_verify_request"
    NEW_SESSION_TICKET = "new_session_ticket"
    END_OF_EARLY_DATA = "end_of_early_data"
    ENCRYPTED_EXTENSIONS = "encrypted_extensions"
    CERTIFICATE = "certificate"
    SERVER_KEY_EXCHANGE = "server_key_exchange"
    CERTIFICATE_REQUEST = "certificate_request"
    SERVER_HELLO_DONE = "server_hello_done"
    CERTIFICATE_VERIFY = "certificate_verify"
    CLIENT_KEY_EXCHANGE = "client_key_exchange"
    FINISHED = "finished"
    CERTIFICATE_URL = "certificate_url"
    CERTIFICATE_STATUS = "certificate_status"
    SUPPLEMENTAL_DATA = "supplemental_data"
    KEY_UPDATE = "key_update"
    MESSAGE_HASH = "message_hash"
    CHANGE_CIPHER_SPEC = "change_cipher_spec"
    ALERT = "alert"
    HEARTBEAT = "heartbeat"
    UNKNOWN = "unknown"


class HandshakeMessage(BaseModel):
    """One evidence-linked handshake or record message."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: HandshakeMessageKind
    direction: StreamDirection
    history_letter: str = Field(min_length=1, max_length=1)
    frame_number: int | None = Field(default=None, ge=1)
    evidence_state: EvidenceState


class TlsVersionEvidence(BaseModel):
    """Negotiated version. `supported_versions` wins over the legacy record version."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    selected: str | None = None
    source: VersionSource | None = None
    evidence_state: EvidenceState
    legacy_record_version: str | None = None
    server_supported_version: str | None = None
    client_supported_versions: list[str] = Field(default_factory=list)


class CipherSuiteEvidence(BaseModel):
    """Selected cipher suite identified by canonical IANA name and hex code."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str | None = None
    code: str | None = None
    evidence_state: EvidenceState


class KeyExchangeEvidence(BaseModel):
    """Version-aware key-exchange classification. No weakness or FS judgment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mechanism: str | None = None
    evidence_state: EvidenceState
    source_fields: list[str] = Field(default_factory=list)
    selected_group: str | None = None
    selected_group_code: int | None = Field(default=None, ge=0, le=65535)
    dh_param_size: int | None = Field(default=None, ge=0)
    psk_key_exchange_modes: list[str] = Field(default_factory=list)


class HandshakeSignatureEvidence(BaseModel):
    """TLS handshake CertificateVerify signature algorithm, not the X.509 cert signature."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    algorithm: str | None = None
    evidence_state: EvidenceState


class TlsHandshake(BaseModel):
    """TLS handshake record linked to a `Flow` by Zeek `uid`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    uid: str
    ssl_history: str
    established: bool
    resumed: bool
    hello_retry_request: bool
    last_alert: str | None = None
    visibility: HandshakeVisibility
    version: TlsVersionEvidence
    cipher_suite: CipherSuiteEvidence
    key_exchange: KeyExchangeEvidence
    messages: list[HandshakeMessage] = Field(default_factory=list)
    server_certificate_state: EvidenceState
    certificate_verify_state: EvidenceState
    certificate_verify_signature: HandshakeSignatureEvidence
    evidence_state: EvidenceState


def _rebuild_evidence_document() -> None:
    """Resolve `TlsHandshake` on `EvidenceDocument` without an import cycle."""

    from securemail.domain.evidence.certificate import CertificateEvidence
    from securemail.domain.evidence.flow import Flow
    from securemail.domain.evidence.run import EvidenceDocument
    from securemail.domain.evidence.session import EmailSession
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
