"""Implicit TLS correlation uses selected ALPN, never the port number alone."""

from securemail.domain.evidence.run import EvidenceState
from securemail.domain.evidence.session import MailProtocol
from securemail.domain.policies.starttls.implicit_tls import correlate_implicit_tls


def test_negotiated_imap_alpn_correlates() -> None:
    result = correlate_implicit_tls(
        responder_port=993,
        tls_on_connection=True,
        negotiated_alpn="imap",
        alpn_frames=(5,),
    )
    assert result.correlated_protocol is MailProtocol.IMAP
    assert result.evidence_state is EvidenceState.OBSERVED
    assert result.source == "alpn"
    assert result.evidence_frames == [5]


def test_smtp_alpn_on_submission_port() -> None:
    result = correlate_implicit_tls(
        responder_port=465,
        tls_on_connection=True,
        negotiated_alpn="smtp",
        alpn_frames=(3, 3, 4),
    )
    assert result.correlated_protocol is MailProtocol.SMTP
    assert result.source == "alpn"
    assert result.evidence_frames == [3, 4]


def test_port_only_tls_is_indeterminate() -> None:
    result = correlate_implicit_tls(
        responder_port=993,
        tls_on_connection=True,
        negotiated_alpn=None,
    )
    assert result.correlated_protocol is None
    assert result.evidence_state is EvidenceState.INDETERMINATE
    assert result.source == "none"


def test_offered_alpn_without_selection_is_indeterminate() -> None:
    result = correlate_implicit_tls(
        responder_port=995,
        tls_on_connection=True,
        negotiated_alpn="",
    )
    assert result.correlated_protocol is None
    assert result.evidence_state is EvidenceState.INDETERMINATE


def test_starttls_port_without_alpn_is_not_observable() -> None:
    result = correlate_implicit_tls(
        responder_port=143,
        tls_on_connection=True,
        negotiated_alpn=None,
    )
    assert result.correlated_protocol is None
    assert result.evidence_state is EvidenceState.NOT_OBSERVABLE
    assert result.source is None
