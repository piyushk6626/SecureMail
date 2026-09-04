"""Step 0 fixture: empty capture through the real CLI path."""

from __future__ import annotations

import json
from pathlib import Path

from tests.support.fixture_harness import DEFAULT_FIXTURE_ANALYSIS_TIME, repo_root, run_fixture
from typer.testing import CliRunner

from securemail.bootstrap import create_cli
from securemail.domain.evidence.run import EvidenceDocument


def test_empty_fixture_matches_expected_json() -> None:
    run_fixture("empty")


def test_empty_analyze_is_byte_identical(tmp_path: Path) -> None:
    capture = repo_root() / "tests" / "fixtures" / "empty" / "capture.pcapng"
    runner = CliRunner()
    app = create_cli()
    first = tmp_path / "one.json"
    second = tmp_path / "two.json"
    result_one = runner.invoke(
        app,
        [
            "analyze",
            str(capture),
            "--out",
            str(first),
            "--analysis-time",
            DEFAULT_FIXTURE_ANALYSIS_TIME,
        ],
    )
    result_two = runner.invoke(
        app,
        [
            "analyze",
            str(capture),
            "--out",
            str(second),
            "--analysis-time",
            DEFAULT_FIXTURE_ANALYSIS_TIME,
        ],
    )
    assert result_one.exit_code == 0, result_one.output
    assert result_two.exit_code == 0, result_two.output
    assert first.read_bytes() == second.read_bytes()
    document = EvidenceDocument.model_validate(json.loads(first.read_text(encoding="utf-8")))
    identity = document.run_identity
    assert identity.analyzer_bundle_digest
    assert identity.capture_sha256
    assert identity.normalization_schema_version == "v1"
    assert identity.policy_profile.value == "ietf_current"
    assert identity.policy_pack_version
    assert document.findings == []
