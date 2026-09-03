"""Implicit TLS correlation: decoded protocol evidence, never port number alone."""

from __future__ import annotations

from collections.abc import Sequence

from securemail.domain.evidence.run import EvidenceState
from securemail.domain.evidence.session import ImplicitTls, MailProtocol

IMPLICIT_TLS_PORTS = frozenset({465, 993, 995})

_ALPN_TO_PROTOCOL: dict[str, MailProtocol] = {
    "smtp": MailProtocol.SMTP,
    "imap": MailProtocol.IMAP,
    "pop3": MailProtocol.POP3,
}


def protocol_from_alpn(negotiated_alpn: str | None) -> MailProtocol | None:
    """Map a *selected* ALPN identifier to a mail protocol. Offered-only is ignored."""

    if negotiated_alpn is None:
        return None
    return _ALPN_TO_PROTOCOL.get(negotiated_alpn.strip().lower())


def correlate_implicit_tls(
    *,
    responder_port: int,
    tls_on_connection: bool,
    negotiated_alpn: str | None,
    alpn_frames: Sequence[int] = (),
) -> ImplicitTls:
    """Correlate implicit TLS using selected ALPN. Port-only stays indeterminate."""

    frames = sorted({frame for frame in alpn_frames if frame >= 1})
    selected = protocol_from_alpn(negotiated_alpn)
    if selected is not None and tls_on_connection:
        return ImplicitTls(
            correlated_protocol=selected,
            evidence_state=EvidenceState.OBSERVED,
            source="alpn",
            evidence_frames=frames,
        )
    if responder_port in IMPLICIT_TLS_PORTS and tls_on_connection:
        return ImplicitTls(
            correlated_protocol=None,
            evidence_state=EvidenceState.INDETERMINATE,
            source="none",
            evidence_frames=frames,
        )
    if responder_port in IMPLICIT_TLS_PORTS:
        return ImplicitTls(
            correlated_protocol=None,
            evidence_state=EvidenceState.INDETERMINATE,
            source="none",
            evidence_frames=[],
        )
    return ImplicitTls(
        correlated_protocol=None,
        evidence_state=EvidenceState.NOT_OBSERVABLE,
        source=None,
        evidence_frames=[],
    )
