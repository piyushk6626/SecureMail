"""Normalize Zeek `ssl.log` (plus ssl-log-ext) into canonical `TlsHandshake` records."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import cast

from securemail.domain.evidence.flow import Flow, ReconstructionQuality, StreamDirection
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
from securemail.domain.evidence.run import EvidenceState
from securemail.domain.policies.tls.key_exchange import (
    TlsParameterIndex,
    classify_key_exchange,
    psk_mode_name,
)

_MAX_UID_LEN = 64
_MAX_HISTORY_LEN = 100
_MAX_NAME_LEN = 128
_MAX_ALERT_LEN = 64
_MAX_RECORDS = 10_000
_MAX_FRAMES = 10_000
_MAX_HOST_LEN = 253

_TLS_VERSIONS: dict[int, str] = {
    768: "SSLv3",
    769: "TLSv10",
    770: "TLSv11",
    771: "TLSv12",
    772: "TLSv13",
}

# Zeek ssl_history letters (server = lowercase, client = uppercase).
_HISTORY_KIND: dict[str, HandshakeMessageKind] = {
    "^": HandshakeMessageKind.DIRECTION_FLIP,
    "h": HandshakeMessageKind.HELLO_REQUEST,
    "c": HandshakeMessageKind.CLIENT_HELLO,
    "s": HandshakeMessageKind.SERVER_HELLO,
    "j": HandshakeMessageKind.HELLO_RETRY_REQUEST,
    "v": HandshakeMessageKind.HELLO_VERIFY_REQUEST,
    "t": HandshakeMessageKind.NEW_SESSION_TICKET,
    "e": HandshakeMessageKind.END_OF_EARLY_DATA,
    "o": HandshakeMessageKind.ENCRYPTED_EXTENSIONS,
    "x": HandshakeMessageKind.CERTIFICATE,
    "k": HandshakeMessageKind.SERVER_KEY_EXCHANGE,
    "r": HandshakeMessageKind.CERTIFICATE_REQUEST,
    "n": HandshakeMessageKind.SERVER_HELLO_DONE,
    "y": HandshakeMessageKind.CERTIFICATE_VERIFY,
    "g": HandshakeMessageKind.CLIENT_KEY_EXCHANGE,
    "f": HandshakeMessageKind.FINISHED,
    "w": HandshakeMessageKind.CERTIFICATE_URL,
    "u": HandshakeMessageKind.CERTIFICATE_STATUS,
    "a": HandshakeMessageKind.SUPPLEMENTAL_DATA,
    "p": HandshakeMessageKind.KEY_UPDATE,
    "m": HandshakeMessageKind.MESSAGE_HASH,
    "i": HandshakeMessageKind.CHANGE_CIPHER_SPEC,
    "l": HandshakeMessageKind.ALERT,
    "b": HandshakeMessageKind.HEARTBEAT,
    "z": HandshakeMessageKind.UNKNOWN,
}

_TSHARK_TYPE_TO_KIND: dict[int, HandshakeMessageKind] = {
    1: HandshakeMessageKind.CLIENT_HELLO,
    2: HandshakeMessageKind.SERVER_HELLO,
    4: HandshakeMessageKind.NEW_SESSION_TICKET,
    5: HandshakeMessageKind.END_OF_EARLY_DATA,
    8: HandshakeMessageKind.ENCRYPTED_EXTENSIONS,
    11: HandshakeMessageKind.CERTIFICATE,
    12: HandshakeMessageKind.SERVER_KEY_EXCHANGE,
    13: HandshakeMessageKind.CERTIFICATE_REQUEST,
    14: HandshakeMessageKind.SERVER_HELLO_DONE,
    15: HandshakeMessageKind.CERTIFICATE_VERIFY,
    16: HandshakeMessageKind.CLIENT_KEY_EXCHANGE,
    20: HandshakeMessageKind.FINISHED,
    24: HandshakeMessageKind.KEY_UPDATE,
}

# RFC 8446 / IANA TLS SignatureScheme values used for CertificateVerify.
_SIGNATURE_SCHEMES: dict[int, str] = {
    0x0101: "rsa_pkcs1_md5",
    0x0201: "rsa_pkcs1_sha1",
    0x0202: "dsa_sha1",
    0x0203: "ecdsa_sha1",
    0x0401: "rsa_pkcs1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0808: "ed448",
}


def _as_mapping(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return None


def _as_str(value: object, *, max_len: int) -> str | None:
    if isinstance(value, str):
        if not value or len(value) > max_len:
            return None
        return value
    return None


def _as_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value.is_integer() and value >= 0:
        return int(value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _as_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def _as_int_list(value: object, *, limit: int = 64) -> list[int]:
    if isinstance(value, bool):
        return []
    if isinstance(value, int):
        return [value] if value >= 0 else []
    if isinstance(value, str):
        parts = [part.strip() for part in value.split(",") if part.strip()]
        out: list[int] = []
        for part in parts[:limit]:
            parsed = _as_int(part)
            if parsed is not None:
                out.append(parsed)
        return out
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        out = []
        for item in list(value)[:limit]:
            parsed = _as_int(item)
            if parsed is not None:
                out.append(parsed)
        return out
    return []


def _bounded_records(rows: object, *, limit: int = _MAX_RECORDS) -> list[Mapping[str, object]]:
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        return []
    out: list[Mapping[str, object]] = []
    for item in rows[:limit]:
        mapping = _as_mapping(item)
        if mapping is not None:
            out.append(mapping)
    return out


def decode_tls_version(value: object) -> str | None:
    """Map a Zeek numeric or string TLS version to the canonical `TLSv1x` token."""

    if isinstance(value, str):
        text = value.strip()
        if not text or len(text) > 16:
            return None
        compact = text.lower().replace(" ", "").replace(".", "")
        aliases = {
            "tlsv10": "TLSv10",
            "tls10": "TLSv10",
            "tlsv1": "TLSv10",
            "tlsv11": "TLSv11",
            "tls11": "TLSv11",
            "tlsv12": "TLSv12",
            "tls12": "TLSv12",
            "tlsv13": "TLSv13",
            "tls13": "TLSv13",
            "sslv3": "SSLv3",
            "ssl3": "SSLv3",
        }
        if compact in aliases:
            return aliases[compact]
        if text in _TLS_VERSIONS.values():
            return text
        parsed = _as_int(text)
        if parsed is not None:
            return _TLS_VERSIONS.get(parsed)
        return None
    numeric = _as_int(value)
    if numeric is None:
        return None
    return _TLS_VERSIONS.get(numeric)


def messages_from_ssl_history(ssl_history: str) -> list[HandshakeMessage]:
    """Expand Zeek `ssl_history` into ordered message records without frame numbers."""

    messages: list[HandshakeMessage] = []
    for letter in ssl_history[:_MAX_HISTORY_LEN]:
        if letter == "^":
            messages.append(
                HandshakeMessage(
                    kind=HandshakeMessageKind.DIRECTION_FLIP,
                    direction=StreamDirection.ORIG,
                    history_letter=letter,
                    evidence_state=EvidenceState.OBSERVED,
                )
            )
            continue
        kind = _HISTORY_KIND.get(letter.lower())
        if kind is None:
            kind = HandshakeMessageKind.UNKNOWN
        direction = StreamDirection.ORIG if letter.isupper() else StreamDirection.RESP
        messages.append(
            HandshakeMessage(
                kind=kind,
                direction=direction,
                history_letter=letter,
                evidence_state=EvidenceState.INFERRED,
            )
        )
    return messages


def resolve_selected_version(
    row: Mapping[str, object],
    ssl_history: str,
) -> TlsVersionEvidence:
    """Prefer `server_supported_version` over legacy `version` / `server_version`."""

    client_versions = _as_int_list(row.get("client_supported_versions"))
    client_supported = [
        decoded
        for decoded in (decode_tls_version(item) for item in client_versions)
        if decoded is not None
    ]
    server_supported = decode_tls_version(row.get("server_supported_version"))
    legacy = decode_tls_version(row.get("server_version"))
    zeek_version = decode_tls_version(row.get("version"))
    if legacy is None:
        legacy = zeek_version if _has_server_hello(ssl_history) else None
    has_server = _has_server_hello(ssl_history)

    if server_supported is not None and has_server:
        return TlsVersionEvidence(
            selected=server_supported,
            source=VersionSource.SUPPORTED_VERSIONS,
            evidence_state=EvidenceState.OBSERVED,
            legacy_record_version=legacy,
            server_supported_version=server_supported,
            client_supported_versions=client_supported,
        )
    if has_server and (legacy is not None or zeek_version is not None):
        selected = legacy or zeek_version
        return TlsVersionEvidence(
            selected=selected,
            source=VersionSource.LEGACY_RECORD,
            evidence_state=EvidenceState.OBSERVED,
            legacy_record_version=legacy or zeek_version,
            server_supported_version=server_supported,
            client_supported_versions=client_supported,
        )
    if "C" in ssl_history:
        return TlsVersionEvidence(
            selected=None,
            source=None,
            evidence_state=EvidenceState.INCOMPLETE,
            legacy_record_version=legacy,
            server_supported_version=server_supported,
            client_supported_versions=client_supported,
        )
    return TlsVersionEvidence(
        selected=None,
        source=None,
        evidence_state=EvidenceState.NOT_OBSERVABLE,
        legacy_record_version=legacy,
        server_supported_version=server_supported,
        client_supported_versions=client_supported,
    )


def _has_server_hello(ssl_history: str) -> bool:
    return "s" in ssl_history or "j" in ssl_history


def _is_tls13(version: str | None) -> bool:
    return version == "TLSv13"


def _flow_addresses(flow: Flow) -> set[tuple[str, int]]:
    return {(flow.orig.host, flow.orig.port), (flow.resp.host, flow.resp.port)}


def _frame_endpoints(frame: Mapping[str, object]) -> list[tuple[str, int]]:
    src_port = _as_int(frame.get("tcp.srcport"))
    dst_port = _as_int(frame.get("tcp.dstport"))
    endpoints: list[tuple[str, int]] = []
    for host_key in ("ip.src", "ipv6.src"):
        host = _as_str(frame.get(host_key), max_len=_MAX_HOST_LEN)
        if host is not None and src_port is not None and src_port <= 65535:
            endpoints.append((host, src_port))
    for host_key in ("ip.dst", "ipv6.dst"):
        host = _as_str(frame.get(host_key), max_len=_MAX_HOST_LEN)
        if host is not None and dst_port is not None and dst_port <= 65535:
            endpoints.append((host, dst_port))
    return endpoints


def _match_frame_uid(frame: Mapping[str, object], flows: Sequence[Flow]) -> str | None:
    endpoints = set(_frame_endpoints(frame))
    if len(endpoints) < 2:
        return None
    matches = [
        flow.uid
        for flow in flows
        if endpoints.issubset(_flow_addresses(flow)) or endpoints == _flow_addresses(flow)
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def _tshark_handshake_types(frame: Mapping[str, object]) -> list[int]:
    return _as_int_list(frame.get("tls.handshake.type"), limit=16)


def _tshark_selected_group(frame: Mapping[str, object]) -> int | None:
    raw = frame.get("tls.handshake.extensions_key_share_selected_group")
    if raw is None:
        raw = frame.get("tls.handshake.extensions.key_share.selected_group")
    parsed = _as_int(raw)
    if parsed is not None:
        return parsed
    if isinstance(raw, str) and raw.lower().startswith("0x"):
        try:
            return int(raw, 16)
        except ValueError:
            return None
    return None


def _attach_frames(
    messages: list[HandshakeMessage],
    frames: Sequence[Mapping[str, object]],
) -> list[HandshakeMessage]:
    pending: dict[HandshakeMessageKind, list[int]] = defaultdict(list)
    for index, message in enumerate(messages):
        if message.kind is HandshakeMessageKind.DIRECTION_FLIP:
            continue
        pending[message.kind].append(index)

    updated = list(messages)
    for frame in frames:
        frame_number = _as_int(frame.get("frame.number"))
        if frame_number is None or frame_number < 1:
            continue
        types = _tshark_handshake_types(frame)
        selected_group = _tshark_selected_group(frame)
        for handshake_type in types:
            kind = _TSHARK_TYPE_TO_KIND.get(handshake_type)
            if handshake_type == 2 and selected_group is not None:
                kind = HandshakeMessageKind.HELLO_RETRY_REQUEST
            if kind is None:
                continue
            indexes = pending.get(kind)
            if not indexes:
                if kind is HandshakeMessageKind.HELLO_RETRY_REQUEST and pending.get(
                    HandshakeMessageKind.SERVER_HELLO
                ):
                    indexes = pending[HandshakeMessageKind.SERVER_HELLO]
                else:
                    continue
            target = indexes.pop(0)
            current = updated[target]
            updated[target] = current.model_copy(
                update={
                    "kind": kind,
                    "frame_number": frame_number,
                    "evidence_state": EvidenceState.OBSERVED,
                }
            )
    return updated


def _visibility(
    *,
    ssl_history: str,
    selected_version: str | None,
    established: bool,
    server_certificate_state: EvidenceState,
    certificate_verify_state: EvidenceState,
) -> HandshakeVisibility:
    if not ssl_history:
        return HandshakeVisibility.NOT_OBSERVABLE
    if _is_tls13(selected_version):
        if (
            server_certificate_state is EvidenceState.OBSERVED
            and certificate_verify_state is EvidenceState.OBSERVED
        ):
            return HandshakeVisibility.FULL
        return HandshakeVisibility.PARTIAL
    saw_certificate = "x" in ssl_history or "n" in ssl_history
    if established and _has_server_hello(ssl_history) and saw_certificate:
        return HandshakeVisibility.FULL
    return HandshakeVisibility.PARTIAL


def _handshake_evidence_state(
    *,
    flow: Flow | None,
    version: TlsVersionEvidence,
    established: bool,
) -> EvidenceState:
    if flow is not None and flow.reconstruction_quality is ReconstructionQuality.CONFLICTING:
        return EvidenceState.CONFLICTING
    truncated_reasons = {
        "snaplen_truncation",
        "segment_gap",
        "capture_loss",
        "midstream_start",
    }
    truncated = (
        flow is not None
        and flow.reconstruction_quality is ReconstructionQuality.INCOMPLETE
        and flow.reason_code is not None
        and flow.reason_code.value in truncated_reasons
    )
    if truncated and not established:
        return EvidenceState.INCOMPLETE
    if version.evidence_state is EvidenceState.INCOMPLETE:
        return EvidenceState.INCOMPLETE
    if version.selected is not None:
        return EvidenceState.OBSERVED
    return version.evidence_state


def _certificate_states(
    ssl_history: str,
    selected_version: str | None,
) -> tuple[EvidenceState, EvidenceState]:
    server_cert = "x" in ssl_history
    server_verify = "y" in ssl_history
    if _is_tls13(selected_version):
        cert_state = EvidenceState.OBSERVED if server_cert else EvidenceState.NOT_OBSERVABLE
        verify_state = EvidenceState.OBSERVED if server_verify else EvidenceState.NOT_OBSERVABLE
        return cert_state, verify_state
    cert_state = EvidenceState.OBSERVED if server_cert else EvidenceState.NOT_OBSERVABLE
    verify_state = EvidenceState.OBSERVED if server_verify else EvidenceState.NOT_OBSERVABLE
    return cert_state, verify_state


def decode_signature_scheme(value: object) -> str | None:
    """Map a TShark SignatureScheme / sig_hash_alg value to a stable token."""

    if isinstance(value, str):
        text = value.strip()
        if not text or len(text) > _MAX_NAME_LEN:
            return None
        lowered = text.lower().replace("-", "_")
        if lowered.startswith("0x"):
            try:
                parsed_hex = int(lowered, 16)
            except ValueError:
                return lowered
            return _SIGNATURE_SCHEMES.get(parsed_hex, lowered)
        if lowered.isdigit():
            parsed_dec = int(lowered)
            return _SIGNATURE_SCHEMES.get(parsed_dec, lowered)
        return lowered
    parsed = _as_int(value)
    if parsed is None:
        return None
    return _SIGNATURE_SCHEMES.get(parsed, f"0x{parsed:04x}")


def _certificate_verify_signature(
    ssl_history: str,
    frames: Sequence[Mapping[str, object]],
) -> HandshakeSignatureEvidence:
    if "y" not in ssl_history and "Y" not in ssl_history:
        return HandshakeSignatureEvidence(
            algorithm=None,
            evidence_state=EvidenceState.NOT_OBSERVABLE,
        )
    for frame in frames:
        if 15 not in _tshark_handshake_types(frame):
            continue
        raw = frame.get("tls.handshake.sig_hash_alg")
        if raw is None:
            raw = frame.get("tls.handshake.signature_scheme")
        if isinstance(raw, str) and "," in raw:
            raw = raw.split(",")[-1].strip()
        algorithm = decode_signature_scheme(raw)
        if algorithm is not None:
            return HandshakeSignatureEvidence(
                algorithm=algorithm,
                evidence_state=EvidenceState.OBSERVED,
            )
    return HandshakeSignatureEvidence(
        algorithm=None,
        evidence_state=EvidenceState.INCOMPLETE,
    )


def _cipher_evidence(
    row: Mapping[str, object],
    index: TlsParameterIndex,
    *,
    has_server_hello: bool,
) -> CipherSuiteEvidence:
    name = _as_str(row.get("cipher"), max_len=_MAX_NAME_LEN)
    if not has_server_hello:
        return CipherSuiteEvidence(name=None, code=None, evidence_state=EvidenceState.INCOMPLETE)
    if name is None:
        return CipherSuiteEvidence(
            name=None,
            code=None,
            evidence_state=EvidenceState.NOT_OBSERVABLE,
        )
    code = index.cipher_code(name)
    if code is None:
        return CipherSuiteEvidence(name=name, code=None, evidence_state=EvidenceState.INFERRED)
    return CipherSuiteEvidence(name=name, code=code, evidence_state=EvidenceState.OBSERVED)


def _key_exchange_evidence(
    *,
    row: Mapping[str, object],
    version: TlsVersionEvidence,
    index: TlsParameterIndex,
    resumed: bool,
) -> KeyExchangeEvidence:
    server_group = _as_int(row.get("server_key_share_group"))
    client_groups = _as_int_list(row.get("client_key_share_groups"))
    dh_param_size = _as_int(row.get("dh_param_size"))
    psk_modes = _as_int_list(row.get("psk_key_exchange_modes"))
    curve = _as_str(row.get("curve"), max_len=_MAX_NAME_LEN)
    group_name = index.group_name(server_group)
    if group_name is None and curve is not None:
        group_name = curve
        if server_group is None:
            server_group = index.group_code(curve)
    classified = classify_key_exchange(
        negotiated_version=version.selected,
        cipher_suite=_as_str(row.get("cipher"), max_len=_MAX_NAME_LEN),
        server_key_share_group=server_group,
        client_key_share_groups=client_groups,
        dh_param_size=dh_param_size,
        psk_key_exchange_modes=psk_modes,
        curve=curve,
        resumed=resumed,
        group_name=group_name,
    )
    mode_names = [name for name in (psk_mode_name(mode) for mode in psk_modes) if name is not None]
    return KeyExchangeEvidence(
        mechanism=classified.mechanism,
        evidence_state=classified.evidence_state,
        source_fields=list(classified.source_fields),
        selected_group=group_name,
        selected_group_code=server_group,
        dh_param_size=dh_param_size,
        psk_key_exchange_modes=mode_names,
    )


def _handshake_from_row(
    row: Mapping[str, object],
    flow: Flow | None,
    index: TlsParameterIndex,
    frames: Sequence[Mapping[str, object]],
) -> TlsHandshake | None:
    uid = _as_str(row.get("uid"), max_len=_MAX_UID_LEN)
    if uid is None:
        return None
    history = _as_str(row.get("ssl_history"), max_len=_MAX_HISTORY_LEN) or ""
    established = _as_bool(row.get("established")) is True
    resumed = _as_bool(row.get("resumed")) is True
    last_alert = _as_str(row.get("last_alert"), max_len=_MAX_ALERT_LEN)
    version = resolve_selected_version(row, history)
    messages = _attach_frames(messages_from_ssl_history(history), frames)
    hello_retry = any(
        message.kind is HandshakeMessageKind.HELLO_RETRY_REQUEST for message in messages
    )
    if not hello_retry:
        hello_retry = "j" in history
    cipher = _cipher_evidence(row, index, has_server_hello=_has_server_hello(history))
    key_exchange = _key_exchange_evidence(row=row, version=version, index=index, resumed=resumed)
    cert_state, verify_state = _certificate_states(history, version.selected)
    visibility = _visibility(
        ssl_history=history,
        selected_version=version.selected,
        established=established,
        server_certificate_state=cert_state,
        certificate_verify_state=verify_state,
    )
    return TlsHandshake(
        uid=uid,
        ssl_history=history,
        established=established,
        resumed=resumed,
        hello_retry_request=hello_retry,
        last_alert=last_alert,
        visibility=visibility,
        version=version,
        cipher_suite=cipher,
        key_exchange=key_exchange,
        messages=messages,
        server_certificate_state=cert_state,
        certificate_verify_state=verify_state,
        certificate_verify_signature=_certificate_verify_signature(history, frames),
        evidence_state=_handshake_evidence_state(
            flow=flow,
            version=version,
            established=established,
        ),
    )


def normalize_handshakes(
    logs: Mapping[str, list[dict[str, object]]],
    flows: Sequence[Flow],
    tls_parameters: TlsParameterIndex,
    tshark_frames: Sequence[Mapping[str, object]] | None = None,
) -> list[TlsHandshake]:
    """Build top-level handshake records from `ssl.log` plus optional TShark frames."""

    flow_by_uid = {flow.uid: flow for flow in flows}
    frames_by_uid: dict[str, list[Mapping[str, object]]] = defaultdict(list)
    for frame in _bounded_records(tshark_frames or [], limit=_MAX_FRAMES):
        if not _tshark_handshake_types(frame):
            continue
        uid = _match_frame_uid(frame, flows)
        if uid is None:
            continue
        frames_by_uid[uid].append(frame)

    handshakes: list[TlsHandshake] = []
    for row in _bounded_records(logs.get("ssl.log", [])):
        uid = _as_str(row.get("uid"), max_len=_MAX_UID_LEN)
        handshake = _handshake_from_row(
            row,
            flow_by_uid.get(uid) if uid is not None else None,
            tls_parameters,
            frames_by_uid.get(uid or "", ()),
        )
        if handshake is not None:
            handshakes.append(handshake)

    handshakes.sort(
        key=lambda handshake: (
            handshake.uid,
            handshake.ssl_history,
        )
    )
    return handshakes
