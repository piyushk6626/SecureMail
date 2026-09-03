"""Developer workstation checks for Step 0. Prints every check; exits non-zero on failure."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "tools" / "analyzer-bundle.lock"

ZEEK_DIGEST = "sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3"


class Check:
    def __init__(self, name: str) -> None:
        self.name = name
        self.status = "ok"
        self.detail = ""
        self.hint = ""

    def fail(self, detail: str, hint: str) -> None:
        self.status = "fail"
        self.detail = detail
        self.hint = hint

    def skip(self, detail: str) -> None:
        self.status = "skip"
        self.detail = detail


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=False, capture_output=True, text=True)


def check_uv() -> Check:
    result = Check("uv >= 0.11")
    path = shutil.which("uv")
    if path is None:
        result.fail("uv not on PATH", "brew install uv")
        return result
    completed = _run([path, "--version"])
    match = re.search(r"(\d+)\.(\d+)", completed.stdout)
    if not match:
        result.fail(completed.stdout.strip() or "unreadable version", "brew install uv")
        return result
    major, minor = int(match.group(1)), int(match.group(2))
    if (major, minor) < (0, 11):
        result.fail(completed.stdout.strip(), "brew upgrade uv")
    return result


def check_python() -> Check:
    result = Check("python 3.13.x available via uv")
    completed = _run(["uv", "python", "find", "3.13"])
    if completed.returncode != 0:
        result.fail(completed.stderr.strip() or "3.13 not found", "uv python install 3.13")
        return result
    probe = _run(
        ["uv", "run", "--python", "3.13", "python", "-c", "import sys; print(sys.version)"]
    )
    if probe.returncode != 0 or not probe.stdout.startswith("3.13."):
        result.fail(probe.stdout.strip() or probe.stderr.strip(), "uv python install 3.13")
    return result


def check_git_lfs() -> Check:
    result = Check("git-lfs installed")
    completed = _run(["git", "lfs", "version"])
    if completed.returncode != 0:
        result.fail("git-lfs not installed", "brew install git-lfs && git lfs install")
    return result


def check_docker() -> Check:
    result = Check("docker daemon reachable")
    completed = _run(["docker", "info"])
    if completed.returncode != 0:
        result.fail(
            completed.stderr.strip().splitlines()[-1] if completed.stderr else "docker info failed",
            "start Docker Desktop, then re-run make doctor",
        )
    return result


def check_zeek_digest() -> Check:
    result = Check(f"zeek/zeek@{ZEEK_DIGEST[:19]}... matches lock")
    if not LOCK_PATH.is_file():
        result.fail("tools/analyzer-bundle.lock missing", "make analyzer-lock")
        return result
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    if lock.get("zeek_image_digest") != ZEEK_DIGEST:
        result.fail("lock digest mismatch", "make analyzer-lock")
        return result
    inspect = _run(["docker", "image", "inspect", f"zeek/zeek@{ZEEK_DIGEST}"])
    if inspect.returncode != 0:
        manifest = _run(["docker", "manifest", "inspect", f"zeek/zeek@{ZEEK_DIGEST}"])
        if manifest.returncode != 0:
            result.fail(
                "pinned Zeek image is not present and did not resolve",
                f"docker pull zeek/zeek@{ZEEK_DIGEST}",
            )
    return result


def check_pango() -> Check:
    result = Check("pango visible via pkg-config")
    pkg_config = shutil.which("pkg-config") or "/opt/homebrew/bin/pkg-config"
    if not Path(pkg_config).exists():
        result.fail("pkg-config not found", "brew install pkg-config pango")
        return result
    completed = _run([pkg_config, "--modversion", "pango"])
    if completed.returncode != 0:
        result.fail("pango not found via pkg-config", "brew install pango")
        return result
    version = completed.stdout.strip()
    match = re.match(r"(\d+)\.(\d+)", version)
    if not match or (int(match.group(1)), int(match.group(2))) < (1, 58):
        result.fail(f"pango {version} is older than 1.58", "brew install pango")
    return result


def check_openssl() -> Check:
    result = Check("openssl reports OpenSSL (not LibreSSL)")
    if platform.system() == "Darwin":
        binary = "/opt/homebrew/bin/openssl"
        hint = "brew install openssl@3"
    else:
        binary = shutil.which("openssl") or "/usr/bin/openssl"
        hint = "install OpenSSL 3.x"
    if not Path(binary).exists():
        result.fail(f"{binary} not found", hint)
        return result
    completed = _run([binary, "version"])
    text = completed.stdout.strip()
    if "LibreSSL" in text:
        result.fail(text, hint)
        return result
    if not text.startswith("OpenSSL"):
        result.fail(text or "unreadable version", hint)
    return result


def check_node() -> Check:
    result = Check("node/nvm (only required for Step 11)")
    result.skip("only required for Step 11")
    return result


def main() -> None:
    checks = [
        check_uv(),
        check_python(),
        check_git_lfs(),
        check_docker(),
        check_zeek_digest(),
        check_pango(),
        check_openssl(),
        check_node(),
    ]
    first_fail: Check | None = None
    for check in checks:
        if check.status == "ok":
            print(f"[ok]   {check.name}")
        elif check.status == "skip":
            print(f"[skip] {check.name}")
        else:
            print(f"[fail] {check.name}          -> {check.hint}")
            if first_fail is None:
                first_fail = check
    if first_fail is not None:
        sys.exit(1)
    if os.environ.get("SECUREMAIL_CI") == "1":
        print("CI doctor: Docker Desktop-specific checks skipped")


if __name__ == "__main__":
    main()
