"""Load and hash tools/analyzer-bundle.lock. Never write the lock from this module."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TypedDict

from securemail.ports.analyzers import AnalyzerError


class AnalyzerBundleLock(TypedDict):
    zeek_image_digest: str
    tshark_image_digest: str
    zeek_bundle_sha256: str


class AnalyzerDigestMismatchError(AnalyzerError):
    """Raised when a local analyzer digest does not match the lock file."""


class AnalyzerExecutionError(AnalyzerError):
    """Raised when a sandboxed analyzer exits non-zero or exceeds bounds."""


def find_repo_root(start: Path | None = None) -> Path:
    """Walk parents until `tools/analyzer-bundle.lock` and `pyproject.toml` exist."""

    seeds = []
    if start is not None:
        seeds.append(start.resolve())
    seeds.append(Path.cwd().resolve())
    seeds.append(Path(__file__).resolve())
    seen: set[Path] = set()
    for seed in seeds:
        for candidate in [seed, *seed.parents]:
            if candidate in seen:
                continue
            seen.add(candidate)
            lock_path = candidate / "tools" / "analyzer-bundle.lock"
            pyproject = candidate / "pyproject.toml"
            if lock_path.is_file() and pyproject.is_file():
                return candidate
    raise FileNotFoundError("Could not locate tools/analyzer-bundle.lock")


def lockfile_path(repo_root: Path | None = None) -> Path:
    root = repo_root if repo_root is not None else find_repo_root()
    return root / "tools" / "analyzer-bundle.lock"


def load_bundle_lock(path: Path | None = None) -> AnalyzerBundleLock:
    lock_path = path if path is not None else lockfile_path()
    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    required = ("zeek_image_digest", "tshark_image_digest", "zeek_bundle_sha256")
    missing = [key for key in required if key not in payload]
    if missing:
        raise AnalyzerDigestMismatchError(f"analyzer-bundle.lock missing keys: {missing}")
    return AnalyzerBundleLock(
        zeek_image_digest=str(payload["zeek_image_digest"]),
        tshark_image_digest=str(payload["tshark_image_digest"]),
        zeek_bundle_sha256=str(payload["zeek_bundle_sha256"]),
    )


def digest_lockfile_bytes(lock_path: Path) -> str:
    """SHA-256 of the lock file bytes; this is AnalysisRun.analyzer_bundle_digest."""

    return hashlib.sha256(lock_path.read_bytes()).hexdigest()


def hash_directory_tree(root: Path) -> str:
    """Deterministic SHA-256 over relative paths and file contents under `root`."""

    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob("*") if path.is_file())
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def verify_lock(
    lock: AnalyzerBundleLock,
    *,
    zeek_bundle_sha256: str,
    tshark_image_digest: str,
) -> None:
    if lock["zeek_bundle_sha256"] != zeek_bundle_sha256:
        raise AnalyzerDigestMismatchError(
            "zeek/ bundle hash does not match tools/analyzer-bundle.lock"
        )
    if lock["tshark_image_digest"] != tshark_image_digest:
        raise AnalyzerDigestMismatchError(
            "TShark image digest does not match tools/analyzer-bundle.lock"
        )
    expected_zeek = "sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3"
    if lock["zeek_image_digest"] != expected_zeek:
        raise AnalyzerDigestMismatchError(
            "Zeek image digest does not match the pinned zeek/zeek:8.0.10 digest"
        )
