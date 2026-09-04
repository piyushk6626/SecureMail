"""Load checked-in policy packs. No network I/O and no user-supplied paths."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import MappingProxyType
from typing import Final

import yaml  # type: ignore[import-untyped]

from securemail.domain.evidence.run import PolicyProfile
from securemail.domain.policies.rule_engine import PolicyPack, canonical_pack_digest

_RULES_DIR = Path(__file__).resolve().parents[2] / "domain" / "policies" / "rules"
_PROFILE_FILES: MappingProxyType[str, str] = MappingProxyType(
    {
        PolicyProfile.IETF_CURRENT.value: "ietf_current.yaml",
        PolicyProfile.NIST_FEDERAL.value: "nist_federal.yaml",
        PolicyProfile.HISTORICAL_AT_CAPTURE.value: "historical_at_capture.yaml",
    }
)
_MAX_FILE_BYTES: Final[int] = 256 * 1024


class PolicyPackError(ValueError):
    """Raised when a built-in rule pack is missing or malformed."""


class UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    """SafeLoader that rejects duplicate keys, aliases, and custom tags."""


def _construct_mapping(
    loader: yaml.SafeLoader,
    node: yaml.Node,
    deep: bool = False,
) -> dict[object, object]:
    if not isinstance(node, yaml.MappingNode):
        raise PolicyPackError("YAML mapping expected")
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise PolicyPackError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


def _compose_node(self: yaml.composer.Composer, parent: object, index: object) -> yaml.Node:
    event = self.peek_event()
    if isinstance(event, yaml.AliasEvent):
        raise PolicyPackError("YAML aliases are not allowed")
    if getattr(event, "anchor", None):
        raise PolicyPackError("YAML anchors are not allowed")
    return yaml.composer.Composer.compose_node(self, parent, index)


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)
UniqueKeyLoader.compose_node = _compose_node


def load_policy_pack(profile: PolicyProfile | str) -> tuple[PolicyPack, str]:
    """Return the typed pack and its canonical SHA-256 digest."""

    token = profile.value if isinstance(profile, PolicyProfile) else profile
    filename = _PROFILE_FILES.get(token)
    if filename is None:
        raise PolicyPackError(f"unknown policy profile: {token}")
    path = _RULES_DIR / filename
    raw = _read_bounded(path)
    try:
        documents = list(yaml.load_all(raw.decode("utf-8"), Loader=UniqueKeyLoader))
    except yaml.YAMLError as exc:
        raise PolicyPackError(f"rule pack is not valid YAML: {path.name}") from exc
    if len(documents) != 1:
        raise PolicyPackError("rule pack must contain exactly one YAML document")
    payload = documents[0]
    try:
        pack = PolicyPack.model_validate(payload)
    except Exception as exc:
        raise PolicyPackError(f"rule pack failed validation: {exc}") from exc
    if pack.profile.value != token:
        raise PolicyPackError(
            f"rule pack profile {pack.profile.value} does not match requested {token}"
        )
    digest = canonical_pack_digest(pack)
    return pack, digest


def policy_pack_file_digest(profile: PolicyProfile | str) -> str:
    token = profile.value if isinstance(profile, PolicyProfile) else profile
    filename = _PROFILE_FILES.get(token)
    if filename is None:
        raise PolicyPackError(f"unknown policy profile: {token}")
    return hashlib.sha256(_read_bounded(_RULES_DIR / filename)).hexdigest()


def _read_bounded(path: Path) -> bytes:
    if not path.is_file():
        raise PolicyPackError(f"rule pack not found: {path}")
    size = path.stat().st_size
    if size > _MAX_FILE_BYTES:
        raise PolicyPackError("rule pack exceeds the configured size bound")
    return path.read_bytes()
