"""Pinned Docker Zeek runner. Fixed argv only; never a shell string."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from securemail.adapters.analyzers.bundle_lock import (
    AnalyzerDigestMismatchError,
    AnalyzerExecutionError,
    digest_lockfile_bytes,
    find_repo_root,
    hash_directory_tree,
    load_bundle_lock,
    lockfile_path,
)
from securemail.adapters.analyzers.sandbox import (
    ANALYZER_TIMEOUT_SECONDS,
    MAX_OUTPUT_BYTES,
    ZEEK_IMAGE_DIGEST,
    ZEEK_LOCAL_IMAGE,
    assert_fixed_argv,
    sandbox_docker_flags,
)
from securemail.ports.analyzers import ZeekRunResult

_DOCKER = "docker"


class DockerZeekRunner:
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
            ZEEK_LOCAL_IMAGE,
            "zeek",
            "-C",
            "-r",
            "/data/capture.pcapng",
            "LogAscii::use_json=T",
            "/opt/securemail/zeek/site/__load__.zeek",
        ]
        assert_fixed_argv(command)
        return command

    def run(self, capture_path: Path) -> ZeekRunResult:
        lock = load_bundle_lock(self._lock_path)
        bundle_sha = hash_directory_tree(self._repo_root / "zeek")
        if bundle_sha != lock["zeek_bundle_sha256"]:
            raise AnalyzerDigestMismatchError(
                "zeek/ bundle hash does not match tools/analyzer-bundle.lock"
            )
        if lock["zeek_image_digest"] != ZEEK_IMAGE_DIGEST:
            raise AnalyzerDigestMismatchError(
                "Zeek image digest does not match tools/analyzer-bundle.lock"
            )
        self._assert_image_labels(lock["zeek_bundle_sha256"])
        bundle_digest = digest_lockfile_bytes(self._lock_path)

        with tempfile.TemporaryDirectory(prefix="securemail-zeek-") as tmp:
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
                    f"Zeek exceeded {self._timeout_seconds}s timeout"
                ) from exc
            if completed.returncode != 0:
                stderr = completed.stderr.decode("utf-8", errors="replace")
                raise AnalyzerExecutionError(
                    f"Zeek exited {completed.returncode}: {stderr[-2000:]}"
                )
            logs = _read_zeek_json_logs(output_dir)
        return ZeekRunResult(
            image_digest=ZEEK_IMAGE_DIGEST,
            analyzer_bundle_digest=bundle_digest,
            logs=logs,
        )

    def _assert_image_labels(self, expected_bundle_sha: str) -> None:
        inspect = subprocess.run(
            [
                self._docker,
                "image",
                "inspect",
                ZEEK_LOCAL_IMAGE,
                "--format",
                "{{json .Config.Labels}}",
            ],
            check=False,
            capture_output=True,
            timeout=30,
        )
        if inspect.returncode != 0:
            raise AnalyzerDigestMismatchError(
                "securemail/zeek:step0 is missing; run `make zeek-image`"
            )
        rendered = inspect.stdout.decode("utf-8", errors="replace").strip()
        parsed: object = json.loads(rendered) if rendered else {}
        labels = parsed if isinstance(parsed, dict) else {}
        label_bundle = str(labels.get("securemail.zeek_bundle_sha256") or "")
        label_base = str(labels.get("securemail.zeek_base_digest") or "")
        if not label_bundle or not label_base:
            raise AnalyzerDigestMismatchError(
                "securemail/zeek:step0 is missing SecureMail digest labels; "
                "rebuild with make zeek-image"
            )
        if label_bundle != expected_bundle_sha:
            raise AnalyzerDigestMismatchError(
                "securemail/zeek:step0 bundle label does not match tools/analyzer-bundle.lock"
            )
        if label_base != ZEEK_IMAGE_DIGEST:
            raise AnalyzerDigestMismatchError(
                "securemail/zeek:step0 base digest label does not match the pinned Zeek image"
            )


def _read_zeek_json_logs(output_dir: Path) -> dict[str, list[dict[str, object]]]:
    total = 0
    logs: dict[str, list[dict[str, object]]] = {}
    for path in sorted(output_dir.glob("*.log")):
        data = path.read_bytes()
        total += len(data)
        if total > MAX_OUTPUT_BYTES:
            raise AnalyzerExecutionError("Zeek output exceeded the configured size bound")
        records: list[dict[str, object]] = []
        for line in data.splitlines():
            if not line.strip():
                continue
            parsed = json.loads(line.decode("utf-8"))
            if isinstance(parsed, dict):
                records.append(parsed)
        logs[path.name] = records
    return logs
