"""Step 10 `securemail evaluate-ml` CLI and `--advisory` default."""

from __future__ import annotations

import json
from pathlib import Path

from tests.support.fixture_harness import load_golden_report
from tests.support.synthetic_cohorts import (
    default_cohort_dir,
    generate_locked_cohort,
    load_cohort_dir,
    write_cohort_dir,
)
from typer.testing import CliRunner

from securemail.bootstrap import create_cli


def test_evaluate_ml_help_lists_command() -> None:
    result = CliRunner().invoke(create_cli(), ["--help"])
    assert result.exit_code == 0
    assert "evaluate-ml" in result.output


def test_report_advisory_flag_defaults_off() -> None:
    result = CliRunner().invoke(create_cli(), ["report", "--help"])
    assert result.exit_code == 0
    assert "--advisory" in result.output


def test_evaluate_ml_cli_on_locked_cohort(tmp_path: Path) -> None:
    windows, labels, manifest = generate_locked_cohort()
    cohort = tmp_path / "cohort_seeded_v1"
    write_cohort_dir(cohort, windows=windows, labels=labels, manifest=manifest)
    result = CliRunner().invoke(create_cli(), ["evaluate-ml", str(cohort)], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["gates"]["baseline_precision_floor"] is True
    assert payload["gates"]["challenger_precision_lift"] is True
    assert payload["gates"]["lift_ci_excludes_zero"] is True
    assert payload["cohort_id"] == "cohort_seeded_v1"


def test_committed_cohort_matches_locked_generator() -> None:
    windows, labels, manifest = generate_locked_cohort()
    committed = default_cohort_dir()
    assert committed.is_dir()
    loaded_windows, loaded_labels, loaded_manifest = load_cohort_dir(committed)
    assert loaded_windows == windows
    assert loaded_labels == labels
    assert loaded_manifest == manifest


def test_report_without_advisory_leaves_section_empty(tmp_path: Path) -> None:
    golden = tmp_path / "golden_report.json"
    golden.write_text(
        json.dumps(load_golden_report(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = CliRunner().invoke(
        create_cli(),
        ["report", str(golden), "--format", "json", "--out", str(out)],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(out.joinpath("report.json").read_text(encoding="utf-8"))
    assert payload["advisory"]["present"] is False
    assert payload["advisory"]["items"] == []
    assert payload["evidence"]["findings"] == load_golden_report()["evidence"]["findings"]


def test_report_advisory_does_not_change_findings(tmp_path: Path) -> None:
    golden = tmp_path / "golden_report.json"
    golden.write_text(
        json.dumps(load_golden_report(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    result = CliRunner().invoke(
        create_cli(),
        ["report", str(golden), "--format", "json", "--advisory", "--out", str(out)],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(out.joinpath("report.json").read_text(encoding="utf-8"))
    assert payload["evidence"]["findings"] == load_golden_report()["evidence"]["findings"]
    assert payload["advisory"]["present"] is True
    assert payload["advisory"]["items"]
