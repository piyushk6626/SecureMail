"""Rewrite fixture expected.json from the live CLI. Used after analyzer/config changes."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE_ANALYSIS_TIME = "2026-09-04T12:00:00Z"


def _analyze_args(base: Path) -> list[str]:
    config_path = base / "analyze.json"
    payload: dict[str, Any] = {}
    if config_path.is_file():
        loaded = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise SystemExit(f"analyze.json must be an object: {config_path}")
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


def main() -> None:
    from securemail.bootstrap import create_cli

    selected = sys.argv[1:]
    fixtures = sorted(
        path
        for path in (ROOT / "tests" / "fixtures").iterdir()
        if path.is_dir() and (path / "capture.pcapng").is_file()
    )
    if selected:
        fixtures = [path for path in fixtures if path.name in selected]
    runner = CliRunner()
    app = create_cli()
    for base in fixtures:
        capture = base / "capture.pcapng"
        extra = _analyze_args(base)
        with tempfile.TemporaryDirectory(prefix=f"securemail-refresh-{base.name}-") as tmp:
            out = Path(tmp) / "actual.json"
            result = runner.invoke(
                app,
                ["analyze", str(capture), "--out", str(out), *extra],
                catch_exceptions=False,
            )
            if result.exit_code != 0:
                raise SystemExit(f"{base.name} failed: {result.output}")
            (base / "expected.json").write_text(out.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"updated {base.name}")


if __name__ == "__main__":
    main()
