"""X.509 path validation at an explicit verification time. No network, no identity check."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from cryptography import x509
from cryptography.x509.verification import (
    ExtensionPolicy,
    PolicyBuilder,
    Store,
    VerificationError,
)

from securemail.domain.evidence.certificate import MAX_CHAIN_DEPTH

TRUST_PROFILE_ID = "offline_v1"


class PathReasonCode(StrEnum):
    """Stable path-validation failure codes. Never emit a bare false without one."""

    SELF_SIGNED = "self_signed"
    MISSING_INTERMEDIATE = "missing_intermediate"
    UNTRUSTED_ISSUER = "untrusted_issuer"
    EXPIRED_AT_VERIFICATION_TIME = "expired_at_verification_time"
    NOT_YET_VALID_AT_VERIFICATION_TIME = "not_yet_valid_at_verification_time"
    SIGNATURE_VERIFICATION_FAILED = "signature_verification_failed"
    MAX_CHAIN_DEPTH_EXCEEDED = "max_chain_depth_exceeded"
    INVALID_EXTENSIONS = "invalid_extensions"
    SYNTAX_INVALID_LEAF = "syntax_invalid_leaf"
    CERTIFICATE_NOT_OBSERVED = "certificate_not_observed"
    CAPTURE_TIME_UNAVAILABLE = "capture_time_unavailable"


@dataclass(frozen=True)
class TrustStoreSnapshot:
    """Pinned offline anchors. Built by the trust-store adapter; consumed as data."""

    profile_id: str
    digest: str
    store: Store
    anchors: tuple[x509.Certificate, ...]


@dataclass(frozen=True)
class ChainValidationInput:
    leaf: x509.Certificate
    intermediates: tuple[x509.Certificate, ...]
    trust_store: TrustStoreSnapshot
    verification_time: datetime


@dataclass(frozen=True)
class ChainValidationResult:
    valid: bool | None
    reason_codes: tuple[str, ...]


def build_trust_snapshot(
    anchors: Sequence[x509.Certificate],
    *,
    profile_id: str,
    digest: str,
) -> TrustStoreSnapshot:
    if not anchors:
        raise ValueError("trust store requires at least one anchor")
    return TrustStoreSnapshot(
        profile_id=profile_id,
        digest=digest,
        store=Store(list(anchors)),
        anchors=tuple(anchors),
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _is_self_signed(certificate: x509.Certificate) -> bool:
    return certificate.subject == certificate.issuer


def _anchor_subjects(snapshot: TrustStoreSnapshot) -> set[x509.Name]:
    return {anchor.subject for anchor in snapshot.anchors}


def _map_verification_failure(
    *,
    leaf: x509.Certificate,
    intermediates: Sequence[x509.Certificate],
    snapshot: TrustStoreSnapshot,
    verification_time: datetime,
    error: VerificationError,
) -> tuple[str, ...]:
    message = str(error).lower()
    instant = _as_utc(verification_time)
    not_before = leaf.not_valid_before_utc
    not_after = leaf.not_valid_after_utc
    if "not valid at validation time" in message:
        if instant > not_after:
            return (PathReasonCode.EXPIRED_AT_VERIFICATION_TIME,)
        if instant < not_before:
            return (PathReasonCode.NOT_YET_VALID_AT_VERIFICATION_TIME,)
        return (PathReasonCode.EXPIRED_AT_VERIFICATION_TIME,)
    if "signature" in message:
        return (PathReasonCode.SIGNATURE_VERIFICATION_FAILED,)
    if "extension" in message or "eku" in message or "basic constraints" in message:
        return (PathReasonCode.INVALID_EXTENSIONS,)
    if "path length" in message or "chain depth" in message or "maximum" in message:
        return (PathReasonCode.MAX_CHAIN_DEPTH_EXCEEDED,)
    if _is_self_signed(leaf) and leaf.subject not in _anchor_subjects(snapshot):
        return (PathReasonCode.SELF_SIGNED,)
    if not intermediates and leaf.issuer not in _anchor_subjects(snapshot):
        return (PathReasonCode.MISSING_INTERMEDIATE,)
    return (PathReasonCode.UNTRUSTED_ISSUER,)


def validate_certificate_path(payload: ChainValidationInput) -> ChainValidationResult:
    """Path-only validation. Hostname matching is a separate function."""

    chain_length = 1 + len(payload.intermediates)
    if chain_length > MAX_CHAIN_DEPTH:
        return ChainValidationResult(
            valid=False,
            reason_codes=(PathReasonCode.MAX_CHAIN_DEPTH_EXCEEDED,),
        )
    instant = _as_utc(payload.verification_time)
    verifier = (
        PolicyBuilder()
        .store(payload.trust_store.store)
        .time(instant)
        .max_chain_depth(MAX_CHAIN_DEPTH)
        .extension_policies(
            ca_policy=ExtensionPolicy.webpki_defaults_ca(),
            ee_policy=ExtensionPolicy.permit_all(),
        )
        .build_client_verifier()
    )
    try:
        verifier.verify(payload.leaf, list(payload.intermediates))
    except VerificationError as exc:
        return ChainValidationResult(
            valid=False,
            reason_codes=_map_verification_failure(
                leaf=payload.leaf,
                intermediates=payload.intermediates,
                snapshot=payload.trust_store,
                verification_time=instant,
                error=exc,
            ),
        )
    return ChainValidationResult(valid=True, reason_codes=())
