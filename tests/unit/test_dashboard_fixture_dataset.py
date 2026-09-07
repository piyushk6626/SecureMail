"""Standalone dashboard fixture dataset generator tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from securemail.domain.reports.schema import CanonicalReport


def test_dataset_contains_every_capture_fixture_and_valid_dashboard_reports(tmp_path: Path) -> None:
    output_root = tmp_path / "dataset"
    completed = subprocess.run(
        [
            sys.executable,
            "tools/build_dashboard_fixture_dataset.py",
            "--out",
            str(output_root),
            "--generated-at",
            "2026-09-06T00:00:00Z",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr

    catalog = json.loads((output_root / "catalog.json").read_text(encoding="utf-8"))
    expected_cases = sorted(
        path.parent
        for path in Path("tests/fixtures").glob("*/expected.json")
        if (path.parent / "capture.pcapng").is_file() or (path.parent / "capture.pcap").is_file()
    )
    dashboard_catalog = json.loads(
        Path("tests/fixtures/dashboard/catalog.json").read_text(encoding="utf-8")
    )
    dashboard_case_ids = {item["case_id"] for item in dashboard_catalog["reports"]}
    assert len(catalog["reports"]) == len(expected_cases) + len(dashboard_case_ids)
    assert {item["case_id"] for item in catalog["reports"]} == {
        f"fixture-{path.name}" for path in expected_cases
    } | dashboard_case_ids

    for fixture_dir in expected_cases:
        expected = json.loads((fixture_dir / "expected.json").read_text(encoding="utf-8"))
        report_path = output_root / f"fixture-{fixture_dir.name}.report.json"
        report = CanonicalReport.model_validate_json(report_path.read_bytes())
        assert report.evidence.model_dump(mode="json") == expected
        assert report.manifest.case_id == f"fixture-{fixture_dir.name}"

    for case_id in dashboard_case_ids:
        report_path = output_root / f"{case_id}.report.json"
        dashboard_report = CanonicalReport.model_validate_json(report_path.read_bytes())
        assert dashboard_report.manifest.case_id == case_id


def test_dataset_selection_and_configuration_are_changeable(tmp_path: Path) -> None:
    config_path = tmp_path / "dataset.json"
    output_root = tmp_path / "selected"
    config_path.write_text(
        json.dumps(
            {
                "output_root": str(output_root),
                "case_id_prefix": "demo-",
                "include": ["tls13_*"],
                "exclude": ["*public_corpus"],
                "max_cases": 2,
                "include_analyst_notes": False,
                "include_dashboard_cases": False,
                "dependency_versions": {"dataset_generator": "test"},
            }
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "tools/build_dashboard_fixture_dataset.py", "--config", str(config_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    catalog = json.loads((output_root / "catalog.json").read_text(encoding="utf-8"))
    assert [item["case_id"] for item in catalog["reports"]] == [
        "demo-tls13_full_handshake",
        "demo-tls13_hello_retry_request",
    ]
    report = json.loads(
        (output_root / "demo-tls13_full_handshake.report.json").read_text(encoding="utf-8")
    )
    assert report["analyst_conclusions"] == {"present": False, "notes": []}
    assert report["manifest"]["dependency_versions"] == {"dataset_generator": "test"}
