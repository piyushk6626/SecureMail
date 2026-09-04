"""Policy-pack loader rejects aliases, duplicates, oversize files, and unknown profiles."""

from pathlib import Path

import pytest
import yaml

from securemail.adapters.reference_data.policy_packs import (
    PolicyPackError,
    UniqueKeyLoader,
    load_policy_pack,
)
from securemail.domain.evidence.run import PolicyProfile
from securemail.domain.policies.rule_engine import canonical_pack_digest


def test_builtin_packs_load_and_hash() -> None:
    seen: set[str] = set()
    for profile in PolicyProfile:
        pack, digest = load_policy_pack(profile)
        assert pack.profile is profile
        assert len(digest) == 64
        assert digest == canonical_pack_digest(pack)
        assert digest not in seen
        seen.add(digest)


def test_unknown_profile_is_rejected() -> None:
    with pytest.raises(PolicyPackError, match="unknown policy profile"):
        load_policy_pack("organization_example")


def test_loader_rejects_anchors_and_aliases() -> None:
    with pytest.raises(PolicyPackError, match="anchor|alias"):
        yaml.load("a: &x 1\nb: *x\n", Loader=UniqueKeyLoader)


def test_loader_rejects_duplicate_keys() -> None:
    with pytest.raises(PolicyPackError, match="duplicate YAML key"):
        yaml.load("profile: ietf_current\nprofile: nist_federal\n", Loader=UniqueKeyLoader)


def test_loader_rejects_oversize_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "ietf_current.yaml"
    path.write_bytes(b"x" * 100)
    monkeypatch.setattr(
        "securemail.adapters.reference_data.policy_packs._RULES_DIR",
        tmp_path,
    )
    monkeypatch.setattr(
        "securemail.adapters.reference_data.policy_packs._MAX_FILE_BYTES",
        10,
    )
    with pytest.raises(PolicyPackError, match="size bound"):
        load_policy_pack(PolicyProfile.IETF_CURRENT)
