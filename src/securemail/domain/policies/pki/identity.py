"""RFC 9525 service identity matching. SAN only; never Common Name fallback."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import ip_address
from typing import Literal

from cryptography import x509

_MAX_DNS_NAME = 253
_MAX_SAN_ENTRIES = 32


class IdentityReasonCode(StrEnum):
    SAN_MISMATCH = "san_mismatch"
    SAN_MISSING = "san_missing"
    REFERENCE_IDENTITY_UNAVAILABLE = "reference_identity_unavailable"


@dataclass(frozen=True)
class SanEntry:
    kind: Literal["dns", "ip"]
    value: str


@dataclass(frozen=True)
class IdentityMatchResult:
    match: bool | None
    reason_codes: tuple[str, ...]


def extract_san_entries(certificate: x509.Certificate) -> tuple[SanEntry, ...]:
    """Return dNSName and iPAddress SAN entries. Ignores CN and other name forms."""

    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return ()
    entries: list[SanEntry] = []
    for general_name in extension.value:
        if len(entries) >= _MAX_SAN_ENTRIES:
            break
        if isinstance(general_name, x509.DNSName):
            normalized = _normalize_dns(general_name.value)
            if normalized is not None:
                entries.append(SanEntry(kind="dns", value=normalized))
            continue
        if isinstance(general_name, x509.IPAddress):
            entries.append(SanEntry(kind="ip", value=str(general_name.value)))
    return tuple(entries)


def match_service_identity(
    *,
    reference_identity: str | None,
    san_entries: Sequence[SanEntry],
) -> IdentityMatchResult:
    """Match a declared reference identity against SAN entries. No CN fallback."""

    if reference_identity is None or not reference_identity.strip():
        return IdentityMatchResult(
            match=None,
            reason_codes=(IdentityReasonCode.REFERENCE_IDENTITY_UNAVAILABLE,),
        )
    if not san_entries:
        return IdentityMatchResult(match=False, reason_codes=(IdentityReasonCode.SAN_MISSING,))
    reference_ip = _as_ip(reference_identity)
    if reference_ip is not None:
        expected = str(reference_ip)
        if any(entry.kind == "ip" and entry.value == expected for entry in san_entries):
            return IdentityMatchResult(match=True, reason_codes=())
        return IdentityMatchResult(match=False, reason_codes=(IdentityReasonCode.SAN_MISMATCH,))
    hostname = _normalize_dns(reference_identity)
    if hostname is None:
        return IdentityMatchResult(match=False, reason_codes=(IdentityReasonCode.SAN_MISMATCH,))
    for entry in san_entries:
        if entry.kind != "dns":
            continue
        if _dns_name_matches(pattern=entry.value, hostname=hostname):
            return IdentityMatchResult(match=True, reason_codes=())
    return IdentityMatchResult(match=False, reason_codes=(IdentityReasonCode.SAN_MISMATCH,))


def _as_ip(value: str) -> object | None:
    try:
        return ip_address(value.strip())
    except ValueError:
        return None


def _normalize_dns(value: str) -> str | None:
    text = value.strip().rstrip(".").lower()
    if not text or len(text) > _MAX_DNS_NAME or " " in text:
        return None
    labels = text.split(".")
    if any(not label for label in labels):
        return None
    encoded: list[str] = []
    for label in labels:
        if label == "*":
            encoded.append(label)
            continue
        if len(label) > 63:
            return None
        try:
            encoded.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            return None
    return ".".join(encoded)


def _dns_name_matches(*, pattern: str, hostname: str) -> bool:
    if "*" not in pattern:
        return pattern == hostname
    if not pattern.startswith("*.") or pattern.count("*") != 1:
        return False
    pattern_labels = pattern.split(".")
    host_labels = hostname.split(".")
    if len(pattern_labels) < 2 or len(pattern_labels) != len(host_labels):
        return False
    if pattern_labels[0] != "*":
        return False
    if not host_labels[0] or host_labels[0] == "*":
        return False
    return host_labels[1:] == pattern_labels[1:]
