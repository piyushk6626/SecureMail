"""Step 8 synthetic finding fixtures through the real `securemail score` CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.support.fixture_harness import repo_root, run_score_fixture
from typer.testing import CliRunner

from securemail.api.cli.commands.score import MAX_SCORE_INPUT_BYTES
from securemail.bootstrap import create_cli

CASES = (
    "mixed_severity",
    "many_low_severity_one_endpoint",
    "recurring_sessions",
    "coverage_denominators",
)


def _expected_case(name: str) -> dict[str, object]:
    path = repo_root() / "tests" / "fixtures" / "synthetic_findings" / "expected.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    case = payload["cases"][name]
    assert isinstance(case, dict)
    return case


@pytest.mark.parametrize("case_name", CASES)
def test_score_fixture_matches_expected_json(case_name: str) -> None:
    run_score_fixture(case_name)


def test_mixed_severity_orders_high_above_informational() -> None:
    expected = _expected_case("mixed_severity")
    findings = expected["prioritized_findings"]
    assert isinstance(findings, list)
    codes = [item["code"] for item in findings]
    assert codes[0] == "TLS_NEGOTIATED_TLS10"
    assert codes[-1] == "TLS_FORWARD_SECRECY_INDETERMINATE"
    assert codes.index("TLS_NEGOTIATED_TLS10") < codes.index("TLS_CIPHER_CBC")
    assert codes.index("TLS_CIPHER_CBC") < codes.index("CERT_EXPIRED_AT_CAPTURE")
    scores = [item["score"] for item in findings]
    assert scores == [90, 66, 61, 36, 9]


def test_dedup_collapses_session_findings() -> None:
    expected = _expected_case("many_low_severity_one_endpoint")
    findings = expected["prioritized_findings"]
    assert isinstance(findings, list)
    assert len(findings) == 2
    by_code = {item["code"]: item for item in findings}
    collapsed = by_code["MAIL_ACCESS_CLEARTEXT"]
    assert collapsed["recurrence_count"] == 4
    assert len(collapsed["contributing_finding_ids"]) == 4
    assert collapsed["components"]["recurrence"] == 6
    assert collapsed["score"] == 44


def test_recurrence_uses_unique_sessions() -> None:
    expected = _expected_case("recurring_sessions")
    findings = expected["prioritized_findings"]
    assert isinstance(findings, list)
    assert len(findings) == 1
    item = findings[0]
    assert item["recurrence_count"] == 3
    assert item["components"]["recurrence"] == 4
    assert item["score"] == 63


def test_coverage_denominators_are_nonzero_and_not_passed() -> None:
    expected = _expected_case("coverage_denominators")
    overall = expected["coverage"]["overall"]
    assert overall["unknown_count"] > 0
    assert overall["not_observable_count"] > 0
    assert overall["passed_count"] != overall["applicable_count"]
    assert (
        overall["passed_count"]
        + overall["failed_count"]
        + overall["unknown_count"]
        + overall["not_observable_count"]
        == overall["applicable_count"]
    )
    assert expected["assessment_state"] == "limited"
    assert expected["risk_score"] is None
    assert expected["coverage"]["by_protocol"]["smtp"]["unknown_count"] > 0
    assert expected["coverage"]["by_category"]["certificate"]["not_observable_count"] > 0


def test_score_help_lists_command() -> None:
    result = CliRunner().invoke(create_cli(), ["--help"])
    assert result.exit_code == 0
    assert "score" in result.output


def test_score_is_byte_identical() -> None:
    app = create_cli()
    path = repo_root() / "tests/fixtures/synthetic_findings/mixed_severity.json"
    first = CliRunner().invoke(app, ["score", str(path)], catch_exceptions=False)
    second = CliRunner().invoke(app, ["score", str(path)], catch_exceptions=False)
    assert first.exit_code == 0
    assert second.exit_code == 0
    assert first.stdout == second.stdout


def test_score_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{", encoding="utf-8")
    result = CliRunner().invoke(create_cli(), ["score", str(path)])
    assert result.exit_code == 1


def test_score_rejects_unknown_fields(tmp_path: Path) -> None:
    path = tmp_path / "extra.json"
    path.write_text(
        '{"schema_version":"securemail.score_request/v1","findings":[],"unexpected":true}',
        encoding="utf-8",
    )
    result = CliRunner().invoke(create_cli(), ["score", str(path)])
    assert result.exit_code == 1


def test_score_rejects_oversized_input(tmp_path: Path) -> None:
    path = tmp_path / "huge.json"
    path.write_bytes(b"{" + b"a" * (MAX_SCORE_INPUT_BYTES + 1))
    result = CliRunner().invoke(create_cli(), ["score", str(path)])
    assert result.exit_code == 1


def test_score_missing_file_exits_2() -> None:
    result = CliRunner().invoke(
        create_cli(),
        ["score", str(repo_root() / "tests/fixtures/synthetic_findings/missing.json")],
    )
    assert result.exit_code == 2
