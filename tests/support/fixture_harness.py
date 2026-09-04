"""End-to-end fixture runner. Diffs produced JSON against expected.json."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

JSONValue = dict[str, Any] | list[Any] | str | int | float | bool | None

# Pinned so goldens stay stable; live CLI still defaults analysis time to now.
DEFAULT_FIXTURE_ANALYSIS_TIME = "2026-09-04T12:00:00Z"


def repo_root() -> Path:
    start = Path(__file__).resolve()
    for candidate in start.parents:
        if (candidate / "pyproject.toml").is_file() and (candidate / "tests" / "fixtures").is_dir():
            return candidate
    raise FileNotFoundError("Could not locate repository root")


def fixture_dir(case_id: str, root: Path | None = None) -> Path:
    path = (root if root is not None else repo_root()) / "tests" / "fixtures" / case_id
    if not path.is_dir():
        raise FileNotFoundError(f"fixture not found: {case_id}")
    return path


def _analyze_args(base: Path) -> list[str]:
    config_path = base / "analyze.json"
    payload: dict[str, Any] = {}
    if config_path.is_file():
        loaded = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise AssertionError(f"analyze.json must be an object: {config_path}")
        payload = loaded
    args: list[str] = [
        "--analysis-time",
        str(payload.get("analysis_time") or DEFAULT_FIXTURE_ANALYSIS_TIME),
    ]
    warning_days = payload.get("expiry_warning_days")
    if warning_days is not None:
        args.extend(["--expiry-warning-days", str(warning_days)])
    expected_hostname = payload.get("expected_hostname")
    if expected_hostname is not None:
        args.extend(["--expected-hostname", str(expected_hostname)])
    policy_profile = payload.get("policy_profile")
    if policy_profile is not None:
        args.extend(["--policy-profile", str(policy_profile)])
    return args


def diff_json(expected: JSONValue, actual: JSONValue, prefix: str = "$") -> list[str]:
    """Return human-readable field-level diffs. Empty list means equality."""

    if type(expected) is not type(actual) and not (expected is None or actual is None):
        return [f"{prefix}: type {type(expected).__name__} != {type(actual).__name__}"]
    if isinstance(expected, Mapping) and isinstance(actual, Mapping):
        diffs: list[str] = []
        expected_keys = set(expected)
        actual_keys = set(actual)
        for key in sorted(expected_keys - actual_keys):
            diffs.append(f"{prefix}.{key}: missing from actual")
        for key in sorted(actual_keys - expected_keys):
            diffs.append(f"{prefix}.{key}: unexpected in actual")
        for key in sorted(expected_keys & actual_keys):
            diffs.extend(diff_json(expected[key], actual[key], f"{prefix}.{key}"))
        return diffs
    if isinstance(expected, Sequence) and not isinstance(expected, (str, bytes)):
        if not isinstance(actual, Sequence) or isinstance(actual, (str, bytes)):
            return [f"{prefix}: expected list, got {type(actual).__name__}"]
        diffs = []
        if len(expected) != len(actual):
            diffs.append(f"{prefix}: length {len(expected)} != {len(actual)}")
        for index, (left, right) in enumerate(zip(expected, actual, strict=False)):
            diffs.extend(diff_json(left, right, f"{prefix}[{index}]"))
        return diffs
    if expected != actual:
        return [f"{prefix}: {expected!r} != {actual!r}"]
    return []


def run_fixture(case_id: str, *, root: Path | None = None) -> Path:
    """Run `securemail analyze` on a fixture and assert expected.json matches."""

    from securemail.bootstrap import create_cli

    base = fixture_dir(case_id, root)
    capture = base / "capture.pcapng"
    expected_path = base / "expected.json"
    if not capture.is_file():
        raise FileNotFoundError(f"missing capture: {capture}")
    if not expected_path.is_file():
        raise FileNotFoundError(f"missing expected.json: {expected_path}")
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    extra_args = _analyze_args(base)

    with tempfile.TemporaryDirectory(prefix=f"securemail-fixture-{case_id}-") as tmp:
        out = Path(tmp) / "actual.json"
        runner = CliRunner()
        result = runner.invoke(
            create_cli(),
            ["analyze", str(capture), "--out", str(out), *extra_args],
            catch_exceptions=False,
        )
        if result.exit_code != 0:
            raise AssertionError(f"securemail analyze failed for {case_id}: {result.output}")
        actual = json.loads(out.read_text(encoding="utf-8"))

    diffs = diff_json(expected, actual)
    if diffs:
        rendered = "\n".join(diffs)
        raise AssertionError(f"fixture {case_id} differed from expected.json:\n{rendered}")
    return capture
