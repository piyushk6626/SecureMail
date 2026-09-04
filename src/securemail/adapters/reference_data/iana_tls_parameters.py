"""Load the checked-in IANA TLS Parameters snapshot. No network I/O."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Final

from securemail.domain.policies.tls.key_exchange import TlsParameterIndex

_DEFAULT_PATH = Path(__file__).with_name("iana-tls-parameters.json")
_MAX_FILE_BYTES: Final[int] = 1_000_000
_MAX_CIPHERS: Final[int] = 2048
_MAX_GROUPS: Final[int] = 512
_MAX_NAME_LEN: Final[int] = 128


class IanaTlsParametersError(ValueError):
    """Raised when the checked-in IANA snapshot is missing or malformed."""


def iana_snapshot_digest(path: Path | None = None) -> str:
    """SHA-256 of the snapshot file bytes. Included in analysis configuration identity."""

    snapshot = path if path is not None else _DEFAULT_PATH
    return hashlib.sha256(_read_bounded(snapshot)).hexdigest()


def load_iana_tls_parameters(path: Path | None = None) -> TlsParameterIndex:
    """Parse and index cipher-suite and supported-group identifiers."""

    snapshot = path if path is not None else _DEFAULT_PATH
    raw = _read_bounded(snapshot)
    digest = hashlib.sha256(raw).hexdigest()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise IanaTlsParametersError("IANA TLS snapshot is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise IanaTlsParametersError("IANA TLS snapshot must be a JSON object")
    snapshot_meta = payload.get("snapshot")
    if not isinstance(snapshot_meta, dict):
        raise IanaTlsParametersError("IANA TLS snapshot is missing snapshot metadata")
    ciphers = _parse_ciphers(payload.get("cipher_suites"))
    groups = _parse_groups(payload.get("supported_groups"))
    cipher_name_to_code = {name: code for code, name in ciphers}
    cipher_code_to_name = {code: name for code, name in ciphers}
    group_code_to_name = {code: name for code, name in groups}
    group_name_to_code = {name: code for code, name in groups}
    return TlsParameterIndex(
        digest=digest,
        cipher_name_to_code=MappingProxyType(cipher_name_to_code),
        cipher_code_to_name=MappingProxyType(cipher_code_to_name),
        group_code_to_name=MappingProxyType(group_code_to_name),
        group_name_to_code=MappingProxyType(group_name_to_code),
    )


def _read_bounded(path: Path) -> bytes:
    if not path.is_file():
        raise IanaTlsParametersError(f"IANA TLS snapshot not found: {path}")
    size = path.stat().st_size
    if size > _MAX_FILE_BYTES:
        raise IanaTlsParametersError("IANA TLS snapshot exceeds the configured size bound")
    return path.read_bytes()


def _parse_ciphers(rows: object) -> list[tuple[str, str]]:
    if not isinstance(rows, list):
        raise IanaTlsParametersError("cipher_suites must be a list")
    if len(rows) > _MAX_CIPHERS:
        raise IanaTlsParametersError("cipher_suites exceeds the configured entry bound")
    out: list[tuple[str, str]] = []
    seen_codes: set[str] = set()
    for item in rows:
        if not isinstance(item, dict):
            raise IanaTlsParametersError("cipher suite entries must be objects")
        code = item.get("code")
        name = item.get("name")
        if not isinstance(code, str) or not isinstance(name, str):
            raise IanaTlsParametersError("cipher suite code and name must be strings")
        if len(name) == 0 or len(name) > _MAX_NAME_LEN:
            raise IanaTlsParametersError("cipher suite name is empty or too long")
        if len(code) != 6 or not code.startswith("0x"):
            raise IanaTlsParametersError(f"invalid cipher suite code: {code}")
        try:
            int(code[2:], 16)
        except ValueError as exc:
            raise IanaTlsParametersError(f"invalid cipher suite code: {code}") from exc
        normalized = f"0x{code[2:].upper()}"
        if normalized in seen_codes:
            continue
        seen_codes.add(normalized)
        out.append((normalized, name))
    return out


def _parse_groups(rows: object) -> list[tuple[int, str]]:
    if not isinstance(rows, list):
        raise IanaTlsParametersError("supported_groups must be a list")
    if len(rows) > _MAX_GROUPS:
        raise IanaTlsParametersError("supported_groups exceeds the configured entry bound")
    out: list[tuple[int, str]] = []
    seen: set[int] = set()
    for item in rows:
        if not isinstance(item, dict):
            raise IanaTlsParametersError("supported group entries must be objects")
        code = item.get("code")
        name = item.get("name")
        if not isinstance(code, int) or isinstance(code, bool) or not isinstance(name, str):
            raise IanaTlsParametersError("supported group code must be int and name a string")
        if code < 0 or code > 65535:
            raise IanaTlsParametersError(f"supported group code out of range: {code}")
        if len(name) == 0 or len(name) > _MAX_NAME_LEN:
            raise IanaTlsParametersError("supported group name is empty or too long")
        if code in seen:
            continue
        seen.add(code)
        out.append((code, name))
    return out
