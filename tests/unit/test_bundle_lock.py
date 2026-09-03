"""Lock mismatches fail closed without silently continuing."""

import json
from pathlib import Path

import pytest

from securemail.adapters.analyzers.bundle_lock import (
    AnalyzerDigestMismatchError,
    hash_directory_tree,
    verify_lock,
)
from securemail.adapters.analyzers.sandbox import ZEEK_IMAGE_DIGEST
from securemail.adapters.analyzers.tshark_runner import DockerTSharkRunner
from securemail.adapters.analyzers.zeek_runner import DockerZeekRunner


def test_verify_lock_rejects_bundle_mismatch(tmp_path: Path) -> None:
    lock = {
        "zeek_image_digest": ZEEK_IMAGE_DIGEST,
        "tshark_image_digest": "a" * 64,
        "zeek_bundle_sha256": "b" * 64,
    }
    with pytest.raises(AnalyzerDigestMismatchError, match="bundle hash"):
        verify_lock(lock, zeek_bundle_sha256="c" * 64, tshark_image_digest="a" * 64)


def test_zeek_runner_fails_closed_on_bundle_mismatch(tmp_path: Path) -> None:
    zeek_dir = tmp_path / "zeek"
    zeek_dir.mkdir()
    (zeek_dir / "site").mkdir()
    (zeek_dir / "site" / "__load__.zeek").write_text("@load base/protocols/conn\n")
    lock_path = tmp_path / "tools" / "analyzer-bundle.lock"
    lock_path.parent.mkdir()
    lock_path.write_text(
        json.dumps(
            {
                "zeek_image_digest": ZEEK_IMAGE_DIGEST,
                "tshark_image_digest": "a" * 64,
                "zeek_bundle_sha256": "0" * 64,
            }
        )
    )
    (tmp_path / "pyproject.toml").write_text("[project]\nname='securemail'\n")
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 16)
    runner = DockerZeekRunner(repo_root=tmp_path, lock_path=lock_path)
    with pytest.raises(AnalyzerDigestMismatchError, match="bundle hash"):
        runner.run(capture)
    assert hash_directory_tree(zeek_dir) != "0" * 64


def test_tshark_runner_fails_closed_on_recipe_mismatch(tmp_path: Path) -> None:
    dockerfile = tmp_path / "docker" / "tshark" / "Dockerfile"
    dockerfile.parent.mkdir(parents=True)
    dockerfile.write_text("FROM debian:trixie-slim\n")
    lock_path = tmp_path / "tools" / "analyzer-bundle.lock"
    lock_path.parent.mkdir()
    lock_path.write_text(
        json.dumps(
            {
                "zeek_image_digest": ZEEK_IMAGE_DIGEST,
                "tshark_image_digest": "0" * 64,
                "zeek_bundle_sha256": "1" * 64,
            }
        )
    )
    (tmp_path / "pyproject.toml").write_text("[project]\nname='securemail'\n")
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"\x0a\x0d\x0d\x0a")
    runner = DockerTSharkRunner(repo_root=tmp_path, lock_path=lock_path)
    with pytest.raises(AnalyzerDigestMismatchError, match="Dockerfile digest"):
        runner.run(capture)
