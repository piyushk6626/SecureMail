"""Pinned Docker TShark runner. Allowlisted fields only; never a shell string."""

from __future__ import annotations

import csv
import hashlib
import io
import os
import subprocess
import tempfile
from pathlib import Path

from securemail.adapters.analyzers.bundle_lock import (
    AnalyzerDigestMismatchError,
    AnalyzerExecutionError,
    find_repo_root,
    load_bundle_lock,
    lockfile_path,
)
from securemail.adapters.analyzers.sandbox import (
    ANALYZER_TIMEOUT_SECONDS,
    MAX_OUTPUT_BYTES,
    TSHARK_LOCAL_IMAGE,
    assert_fixed_argv,
    sandbox_docker_flags,
)
from securemail.ports.analyzers import TSharkRunResult

_DOCKER = "docker"

# Bounded field allowlist. Callers cannot extend this list.
# Mail command verbs/status and TLS handshake types/HRR group only — never
# usernames, passwords, certificate bytes, or key-exchange material.
TSHARK_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "imap.request.command",
    "imap.response.status",
    "imap.tag",
    "imap.isrequest",
    "pop.request.command",
    "pop.response.indicator",
    "smtp.req.command",
    "smtp.response.code",
    "tls.handshake.type",
    "tls.handshake.extensions_key_share_selected_group",
)
TSHARK_DISPLAY_FILTER = "smtp or imap or pop or tls.handshake"


class DockerTSharkRunner:
    def __init__(
        self,
        *,
        repo_root: Path | None = None,
        lock_path: Path | None = None,
        docker_executable: str = _DOCKER,
        timeout_seconds: int = ANALYZER_TIMEOUT_SECONDS,
    ) -> None:
        self._repo_root = repo_root if repo_root is not None else find_repo_root()
        self._lock_path = lock_path if lock_path is not None else lockfile_path(self._repo_root)
        self._docker = docker_executable
        self._timeout_seconds = timeout_seconds

    def argv(self, capture_path: Path, output_dir: Path) -> list[str]:
        capture = capture_path.resolve()
        output = output_dir.resolve()
        tshark_command = [
            "tshark",
            "-n",
            "-r",
            "/data/capture.pcapng",
            "-Y",
            TSHARK_DISPLAY_FILTER,
            "-T",
            "fields",
            "-E",
            "header=y",
            "-E",
            "separator=,",
            "-E",
            "quote=d",
            "-E",
            "occurrence=f",
        ]
        for field in TSHARK_FIELDS:
            tshark_command.extend(["-e", field])
        command = [
            self._docker,
            "run",
            "--rm",
            *sandbox_docker_flags(),
            "--workdir",
            "/data/out",
            "--mount",
            f"type=bind,src={capture},dst=/data/capture.pcapng,readonly=true",
            "--mount",
            f"type=bind,src={output},dst=/data/out",
            TSHARK_LOCAL_IMAGE,
            *tshark_command,
        ]
        assert_fixed_argv(command)
        return command

    def run(self, capture_path: Path) -> TSharkRunResult:
        lock = load_bundle_lock(self._lock_path)
        recipe = tshark_dockerfile_digest(self._repo_root / "docker" / "tshark" / "Dockerfile")
        if recipe != lock["tshark_image_digest"]:
            raise AnalyzerDigestMismatchError(
                "TShark Dockerfile digest does not match tools/analyzer-bundle.lock"
            )
        self._assert_image_present()

        with tempfile.TemporaryDirectory(prefix="securemail-tshark-") as tmp:
            output_dir = Path(tmp)
            os.chmod(output_dir, 0o1777)
            command = self.argv(capture_path, output_dir)
            try:
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    timeout=self._timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise AnalyzerExecutionError(
                    f"TShark exceeded {self._timeout_seconds}s timeout"
                ) from exc
            if completed.returncode != 0:
                stderr = completed.stderr.decode("utf-8", errors="replace")
                raise AnalyzerExecutionError(
                    f"TShark exited {completed.returncode}: {stderr[-2000:]}"
                )
            raw = completed.stdout
            if len(raw) > MAX_OUTPUT_BYTES:
                raise AnalyzerExecutionError("TShark output exceeded the configured size bound")
            frames = _frames_from_fields_csv(raw.decode("utf-8"))
        return TSharkRunResult(image_digest=recipe, frames=frames)

    def _assert_image_present(self) -> None:
        inspect = subprocess.run(
            [self._docker, "image", "inspect", TSHARK_LOCAL_IMAGE],
            check=False,
            capture_output=True,
            timeout=30,
        )
        if inspect.returncode != 0:
            raise AnalyzerDigestMismatchError(
                "securemail/tshark:step0 is missing; run `make tshark-image`"
            )


def tshark_dockerfile_digest(dockerfile: Path) -> str:
    """Platform-stable digest of the TShark image recipe (Dockerfile + pinned FROM)."""

    return hashlib.sha256(dockerfile.read_bytes()).hexdigest()


def _frames_from_fields_csv(text: str) -> list[dict[str, object]]:
    if not text.strip():
        return []
    reader = csv.DictReader(io.StringIO(text))
    frames: list[dict[str, object]] = []
    for row in reader:
        frames.append({key: (value if value != "" else None) for key, value in row.items()})
    return frames
