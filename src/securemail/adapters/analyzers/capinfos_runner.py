"""Pinned Docker capinfos preflight. Fixed argv only; never a shell string."""

from __future__ import annotations

import re
import subprocess
from datetime import UTC, datetime
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
from securemail.adapters.analyzers.tshark_runner import tshark_dockerfile_digest
from securemail.domain.evidence.run import CapturePreflight

_DOCKER = "docker"
_LABEL_RE = re.compile(r"^([^:]+):\s*(.*)$")
_INT_RE = re.compile(r"(\d+)")
_FLOAT_RE = re.compile(r"([0-9]+(?:\.[0-9]+)?)")
_INFERRED_RANGE_RE = re.compile(
    r"inferred:\s*(\d+)\s*(?:bytes)?\s*-\s*(\d+)\s*(?:bytes)?",
    re.IGNORECASE,
)
_INFERRED_SINGLE_RE = re.compile(r"inferred:\s*(\d+)", re.IGNORECASE)
_HDR_SNAPLEN_RE = re.compile(r"file hdr:\s*(\d+)", re.IGNORECASE)

CAPINFOS_ARGV: tuple[str, ...] = (
    "capinfos",
    "-M",
    "-c",
    "-l",
    "-d",
    "-u",
    "-a",
    "-F",
    "/data/capture.pcapng",
)
_START_TIME_RE = re.compile(
    r"(?P<stamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d+))?"
)


def _parse_int(text: str) -> int | None:
    match = _INT_RE.search(text.replace(",", ""))
    if match is None:
        return None
    return int(match.group(1))


def _parse_float(text: str) -> float | None:
    match = _FLOAT_RE.search(text.replace(",", ""))
    if match is None:
        return None
    return float(match.group(1))


def _normalize_precision(text: str) -> str:
    lowered = text.strip().lower()
    if "nanosecond" in lowered:
        return "nanosecond"
    if "microsecond" in lowered:
        return "microsecond"
    if "millisecond" in lowered:
        return "millisecond"
    if "second" in lowered:
        return "second"
    token = lowered.split()[0] if lowered else "unknown"
    return token or "unknown"


def _parse_timestamp(text: str) -> datetime | None:
    stripped = text.strip()
    if not stripped or stripped.lower() in {"n/a", "unknown"}:
        return None
    token = stripped.split()[0]
    try:
        epoch = float(token)
    except ValueError:
        epoch = None
    if epoch is not None and epoch > 1_000_000_000:
        return datetime.fromtimestamp(epoch, tz=UTC)
    match = _START_TIME_RE.search(stripped.replace("T", " ", 1))
    if match is None:
        return None
    stamp = match.group("stamp").replace("T", " ")
    fraction = (match.group("frac") or "0")[:6].ljust(6, "0")
    parsed = datetime.strptime(f"{stamp}.{fraction}", "%Y-%m-%d %H:%M:%S.%f")
    return parsed.replace(tzinfo=UTC)


def parse_capinfos_text(text: str) -> CapturePreflight:
    """Parse long-form `capinfos -M` output into typed preflight evidence."""

    if len(text.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise AnalyzerExecutionError("capinfos output exceeded the configured size bound")
    fields: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        match = _LABEL_RE.match(line)
        if match is None:
            continue
        fields[match.group(1).strip().lower()] = match.group(2).strip()

    packet_count = _parse_int(fields.get("number of packets", ""))
    if packet_count is None:
        raise AnalyzerExecutionError("capinfos output missing packet count")

    precision_raw = (
        fields.get("file timestamp precision") or fields.get("file time precision") or ""
    )
    snaplen_raw = fields.get("packet size limit", "")
    data_raw = fields.get("data size", "")
    duration_raw = fields.get("capture duration", "")
    start_raw = fields.get("first packet time") or fields.get("earliest packet time") or ""

    packet_size_limit: int | None = None
    min_inferred: int | None = None
    max_inferred: int | None = None
    truncated = False
    lowered_snap = snaplen_raw.lower()
    if "not set" not in lowered_snap and "n/a" not in lowered_snap:
        hdr = _HDR_SNAPLEN_RE.search(snaplen_raw)
        if hdr is not None:
            packet_size_limit = int(hdr.group(1))
        elif "inferred" not in lowered_snap:
            packet_size_limit = _parse_int(snaplen_raw)

    range_match = _INFERRED_RANGE_RE.search(snaplen_raw)
    single_match = _INFERRED_SINGLE_RE.search(snaplen_raw)
    if range_match is not None:
        min_inferred = int(range_match.group(1))
        max_inferred = int(range_match.group(2))
        truncated = True
    elif single_match is not None:
        min_inferred = int(single_match.group(1))
        max_inferred = min_inferred
        truncated = True

    return CapturePreflight(
        packet_count=packet_count,
        file_time_precision=_normalize_precision(precision_raw) if precision_raw else "unknown",
        packet_size_limit=packet_size_limit,
        packet_size_limit_min_inferred=min_inferred,
        packet_size_limit_max_inferred=max_inferred,
        truncated_packets_present=truncated,
        original_packet_bytes=_parse_int(data_raw),
        capture_duration_seconds=_parse_float(duration_raw),
        capture_start_time=_parse_timestamp(start_raw),
    )


class DockerCapinfosRunner:
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

    def argv(self, capture_path: Path) -> list[str]:
        capture = capture_path.resolve()
        command = [
            self._docker,
            "run",
            "--rm",
            *sandbox_docker_flags(),
            "--mount",
            f"type=bind,src={capture},dst=/data/capture.pcapng,readonly=true",
            "--entrypoint",
            "capinfos",
            TSHARK_LOCAL_IMAGE,
            *CAPINFOS_ARGV[1:],
        ]
        assert_fixed_argv(command)
        return command

    def run(self, capture_path: Path) -> CapturePreflight:
        lock = load_bundle_lock(self._lock_path)
        recipe = tshark_dockerfile_digest(self._repo_root / "docker" / "tshark" / "Dockerfile")
        if recipe != lock["tshark_image_digest"]:
            raise AnalyzerDigestMismatchError(
                "TShark Dockerfile digest does not match tools/analyzer-bundle.lock"
            )
        self._assert_image_present()
        command = self.argv(capture_path)
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                timeout=self._timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise AnalyzerExecutionError(
                f"capinfos exceeded {self._timeout_seconds}s timeout"
            ) from exc
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace")
            raise AnalyzerExecutionError(
                f"capinfos exited {completed.returncode}: {stderr[-2000:]}"
            )
        raw = completed.stdout
        if len(raw) > MAX_OUTPUT_BYTES:
            raise AnalyzerExecutionError("capinfos output exceeded the configured size bound")
        return parse_capinfos_text(raw.decode("utf-8", errors="replace"))

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
