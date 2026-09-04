"""Version-aware TLS key-exchange classification. No weakness or FS judgment."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from securemail.domain.evidence.run import EvidenceState

_EMPTY_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# RFC 8446 PskKeyExchangeMode values. Not cipher-suite identifiers.
_PSK_KE = 0
_PSK_DHE_KE = 1
_PSK_MODE_NAMES = {
    _PSK_KE: "psk_ke",
    _PSK_DHE_KE: "psk_dhe_ke",
}

# Longest-first IANA key-exchange prefixes in TLS 1.2 suite names.
_TLS12_KX_PREFIXES: tuple[tuple[str, str], ...] = (
    ("ECDHE_PSK", "ECDHE-PSK"),
    ("DHE_PSK", "DHE-PSK"),
    ("RSA_PSK", "RSA-PSK"),
    ("ECDHE", "ECDHE"),
    ("DHE", "DHE"),
    ("ECDH", "ECDH"),
    ("DH", "DH"),
    ("PSK", "PSK"),
    ("RSA", "RSA"),
    ("SRP_SHA", "SRP"),
    ("ECCPWD", "ECCPWD"),
    ("KRB5", "KRB5"),
    ("GOSTR341112_256", "GOST"),
    ("GOSTR341094", "GOST"),
    ("GOSTR341001", "GOST"),
)


@dataclass(frozen=True)
class TlsParameterIndex:
    """Checked-in IANA TLS Parameters snapshot, passed as data into normalizers."""

    digest: str
    cipher_name_to_code: Mapping[str, str]
    cipher_code_to_name: Mapping[str, str]
    group_code_to_name: Mapping[int, str]
    group_name_to_code: Mapping[str, int]

    def cipher_code(self, name: str | None) -> str | None:
        if name is None:
            return None
        return self.cipher_name_to_code.get(name) or self.cipher_name_to_code.get(name.upper())

    def group_name(self, code: int | None) -> str | None:
        if code is None:
            return None
        return self.group_code_to_name.get(code)

    def group_code(self, name: str | None) -> int | None:
        if name is None:
            return None
        if name in self.group_name_to_code:
            return self.group_name_to_code[name]
        lowered = name.lower()
        for candidate, code in self.group_name_to_code.items():
            if candidate.lower() == lowered:
                return code
        return None


def empty_tls_parameter_index() -> TlsParameterIndex:
    """Empty index for unit tests that do not load the snapshot file."""

    return TlsParameterIndex(
        digest=_EMPTY_DIGEST,
        cipher_name_to_code={},
        cipher_code_to_name={},
        group_code_to_name={},
        group_name_to_code={},
    )


@dataclass(frozen=True)
class KeyExchangeClassification:
    """Pure classifier result. `source_fields` names the ssl.log / ext fields used."""

    mechanism: str | None
    evidence_state: EvidenceState
    source_fields: tuple[str, ...]


def psk_mode_name(mode: int) -> str | None:
    return _PSK_MODE_NAMES.get(mode)


def classify_key_exchange(
    *,
    negotiated_version: str | None,
    cipher_suite: str | None,
    server_key_share_group: int | None = None,
    client_key_share_groups: Sequence[int] = (),
    dh_param_size: int | None = None,
    psk_key_exchange_modes: Sequence[int] = (),
    curve: str | None = None,
    resumed: bool = False,
    group_name: str | None = None,
) -> KeyExchangeClassification:
    """Map observed TLS facts to a key-exchange mechanism.

    TLS 1.3 is classified from key_share / groups / PSK modes only — never from
    the cipher-suite name. TLS 1.2 uses the IANA suite-name grammar plus
    observed curve / DH parameter facts.
    """

    if negotiated_version is None:
        return KeyExchangeClassification(None, EvidenceState.INCOMPLETE, ())
    if _is_tls13(negotiated_version):
        return _classify_tls13(
            server_key_share_group=server_key_share_group,
            client_key_share_groups=client_key_share_groups,
            psk_key_exchange_modes=psk_key_exchange_modes,
            curve=curve,
            resumed=resumed,
            group_name=group_name,
        )
    return _classify_tls12(
        cipher_suite=cipher_suite,
        dh_param_size=dh_param_size,
        curve=curve,
    )


def _is_tls13(version: str) -> bool:
    compact = version.lower().replace(" ", "").replace(".", "")
    return compact in {"tlsv13", "tls13", "tlsv1.3"}


def _classify_tls13(
    *,
    server_key_share_group: int | None,
    client_key_share_groups: Sequence[int],
    psk_key_exchange_modes: Sequence[int],
    curve: str | None,
    resumed: bool,
    group_name: str | None,
) -> KeyExchangeClassification:
    sources: list[str] = []
    selected_group = server_key_share_group
    has_key_share = selected_group is not None
    if has_key_share:
        sources.append("server_key_share_group")
    elif curve:
        sources.append("curve")
        has_key_share = True
    family = _group_family(group_name, selected_group, curve)

    psk_only_mode = _PSK_KE in psk_key_exchange_modes and _PSK_DHE_KE not in psk_key_exchange_modes
    offers_dhe_psk = _PSK_DHE_KE in psk_key_exchange_modes
    if psk_key_exchange_modes:
        sources.append("psk_key_exchange_modes")
    if resumed:
        sources.append("resumed")

    if resumed and has_key_share:
        return KeyExchangeClassification("PSK-(EC)DHE", EvidenceState.OBSERVED, tuple(sources))
    if resumed and not has_key_share:
        if psk_only_mode or not offers_dhe_psk:
            return KeyExchangeClassification("PSK", EvidenceState.INFERRED, tuple(sources))
        return KeyExchangeClassification("PSK", EvidenceState.INDETERMINATE, tuple(sources))
    if has_key_share:
        if family is None:
            return KeyExchangeClassification("(EC)DHE", EvidenceState.OBSERVED, tuple(sources))
        return KeyExchangeClassification(family, EvidenceState.OBSERVED, tuple(sources))
    if client_key_share_groups:
        return KeyExchangeClassification(
            None,
            EvidenceState.INCOMPLETE,
            ("client_key_share_groups",),
        )
    return KeyExchangeClassification(None, EvidenceState.INDETERMINATE, tuple(sources))


def _classify_tls12(
    *,
    cipher_suite: str | None,
    dh_param_size: int | None,
    curve: str | None,
) -> KeyExchangeClassification:
    if cipher_suite is None:
        return KeyExchangeClassification(None, EvidenceState.INCOMPLETE, ())
    if _looks_like_tls13_suite(cipher_suite):
        return KeyExchangeClassification(
            None,
            EvidenceState.INDETERMINATE,
            ("cipher",),
        )
    mechanism = _tls12_mechanism_from_name(cipher_suite)
    if mechanism is None:
        return KeyExchangeClassification(None, EvidenceState.INDETERMINATE, ("cipher",))
    sources = ["cipher"]
    if mechanism in {"ECDHE", "ECDH"} and curve:
        sources.append("curve")
    if mechanism in {"DHE", "DH"} and dh_param_size is not None:
        sources.append("dh_param_size")
    return KeyExchangeClassification(mechanism, EvidenceState.INFERRED, tuple(sources))


def _looks_like_tls13_suite(name: str) -> bool:
    if "_WITH_" in name:
        return False
    return (
        name.startswith("TLS_AES_")
        or name.startswith("TLS_CHACHA20_")
        or name.startswith("TLS_AEGIS_")
    )


def _tls12_mechanism_from_name(name: str) -> str | None:
    if not name.startswith("TLS_"):
        return None
    rest = name[4:]
    for prefix, mechanism in _TLS12_KX_PREFIXES:
        if rest == prefix or rest.startswith(prefix + "_"):
            return mechanism
    return None


def _group_family(group_name: str | None, group_code: int | None, curve: str | None) -> str | None:
    label = (group_name or curve or "").lower()
    if "mlkem" in label or "ml-kem" in label:
        return "(EC)DHE"
    if label.startswith("ffdhe") or "ffdhe" in label:
        return "DHE"
    if label:
        return "ECDHE"
    if group_code is None:
        return None
    if 256 <= group_code <= 260:
        return "DHE"
    if group_code >= 4585:
        return "(EC)DHE"
    return "ECDHE"
