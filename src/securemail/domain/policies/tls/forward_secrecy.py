"""Forward secrecy assessment. Version-aware table; never infers reuse or rotation."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from securemail.domain.evidence.handshake import TlsHandshake
from securemail.domain.evidence.run import EvidenceState

_USABLE_STATES = frozenset(
    {
        EvidenceState.OBSERVED,
        EvidenceState.VERIFIED,
        EvidenceState.INFERRED,
    }
)
_TLS12_PRESENT = frozenset({"ECDHE", "DHE"})
_TLS12_ABSENT = frozenset({"RSA", "DH", "ECDH"})
_TLS13_PRESENT = frozenset({"ECDHE", "DHE", "(EC)DHE", "PSK-(EC)DHE"})
_TLS13_INDETERMINATE = frozenset({"PSK"})


class ForwardSecrecyOutcome(StrEnum):
    PRESENT = "present"
    ABSENT = "absent"
    INDETERMINATE = "indeterminate"


class ForwardSecrecyAssessment(BaseModel):
    """Pure assessment consumed by YAML rules. Not a finding by itself."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: ForwardSecrecyOutcome
    evidence_state: EvidenceState
    reason_code: str
    source_fields: tuple[str, ...]


def assess_forward_secrecy(handshake: TlsHandshake) -> ForwardSecrecyAssessment:
    """Classify forward secrecy from already-normalized handshake facts.

    TLS 1.2 ECDHE/DHE → present; static RSA/DH/ECDH → absent; TLS 1.3 observed
    (EC)DHE → present; TLS 1.3 PSK-only or missing/incomplete facts → indeterminate.
    """

    version = handshake.version.selected
    version_state = handshake.version.evidence_state
    mechanism = handshake.key_exchange.mechanism
    kx_state = handshake.key_exchange.evidence_state
    handshake_state = handshake.evidence_state

    if handshake_state in {EvidenceState.INCOMPLETE, EvidenceState.CONFLICTING}:
        return _indeterminate("handshake_incomplete", ("handshake.evidence_state",))
    if version_state not in _USABLE_STATES or version is None:
        return _indeterminate(
            "version_unusable",
            ("handshake.version.selected", "handshake.version.evidence_state"),
        )
    if kx_state in {
        EvidenceState.INCOMPLETE,
        EvidenceState.CONFLICTING,
        EvidenceState.NOT_OBSERVABLE,
    }:
        return _indeterminate(
            "key_exchange_unusable",
            ("handshake.key_exchange.mechanism", "handshake.key_exchange.evidence_state"),
        )
    if mechanism is None:
        return _indeterminate("key_exchange_missing", ("handshake.key_exchange.mechanism",))

    if version == "TLSv13":
        if mechanism in _TLS13_PRESENT and kx_state in _USABLE_STATES:
            return ForwardSecrecyAssessment(
                outcome=ForwardSecrecyOutcome.PRESENT,
                evidence_state=kx_state,
                reason_code="tls13_ephemeral",
                source_fields=("handshake.version.selected", "handshake.key_exchange.mechanism"),
            )
        if mechanism in _TLS13_INDETERMINATE:
            return _indeterminate(
                "tls13_psk_only",
                (
                    "handshake.version.selected",
                    "handshake.key_exchange.mechanism",
                    "handshake.resumed",
                ),
            )
        return _indeterminate(
            "tls13_unknown_mechanism",
            ("handshake.version.selected", "handshake.key_exchange.mechanism"),
        )

    if version in {"TLSv12", "TLSv11", "TLSv10", "SSLv3"}:
        if mechanism in _TLS12_PRESENT and kx_state in _USABLE_STATES:
            return ForwardSecrecyAssessment(
                outcome=ForwardSecrecyOutcome.PRESENT,
                evidence_state=kx_state,
                reason_code="tls12_ephemeral",
                source_fields=("handshake.version.selected", "handshake.key_exchange.mechanism"),
            )
        if mechanism in _TLS12_ABSENT and kx_state in _USABLE_STATES:
            return ForwardSecrecyAssessment(
                outcome=ForwardSecrecyOutcome.ABSENT,
                evidence_state=kx_state,
                reason_code="static_key_exchange",
                source_fields=("handshake.version.selected", "handshake.key_exchange.mechanism"),
            )
        if kx_state is EvidenceState.INDETERMINATE:
            return _indeterminate(
                "key_exchange_indeterminate",
                ("handshake.key_exchange.mechanism", "handshake.key_exchange.evidence_state"),
            )
        return _indeterminate(
            "tls12_unknown_mechanism",
            ("handshake.version.selected", "handshake.key_exchange.mechanism"),
        )

    return _indeterminate("unsupported_version", ("handshake.version.selected",))


def _indeterminate(reason: str, source_fields: tuple[str, ...]) -> ForwardSecrecyAssessment:
    return ForwardSecrecyAssessment(
        outcome=ForwardSecrecyOutcome.INDETERMINATE,
        evidence_state=EvidenceState.INDETERMINATE,
        reason_code=reason,
        source_fields=source_fields,
    )
