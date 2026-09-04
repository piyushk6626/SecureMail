"""Canonical report schema: golden validates; mutations fail."""

from __future__ import annotations

import copy
import json

import pytest
from jsonschema.validators import Draft202012Validator
from pydantic import ValidationError
from tests.support.fixture_harness import load_golden_report, repo_root

from securemail.domain.evidence.run import EvidenceState
from securemail.domain.reports.schema import CanonicalReport, canonical_report_json_schema

SCHEMA_PATH = (
    repo_root() / "src" / "securemail" / "domain" / "reports" / "canonical_report.schema.json"
)


def _schema() -> dict[str, object]:
    payload = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_golden_report_validates_pydantic() -> None:
    report = CanonicalReport.model_validate(load_golden_report())
    states = {item.basis_state for item in report.evidence.findings}
    assert states == set(EvidenceState)
    assert any(
        handshake.server_certificate_state is EvidenceState.NOT_OBSERVABLE
        for handshake in report.evidence.handshakes
    )
    banner = report.evidence.sessions[0].events[0].text
    assert banner is not None
    assert "<script>" in banner
    assert "\u0007" in banner
    assert "\u202e" in banner


def test_golden_report_validates_json_schema() -> None:
    Draft202012Validator(_schema()).validate(load_golden_report())


def test_json_schema_snapshot_matches_model() -> None:
    generated = json.dumps(canonical_report_json_schema(), indent=2, sort_keys=True) + "\n"
    assert generated == SCHEMA_PATH.read_text(encoding="utf-8")


def test_json_schema_forbids_additional_properties() -> None:
    schema = _schema()
    assert schema.get("additionalProperties") is False
    required = schema.get("required")
    assert isinstance(required, list)
    assert "manifest" in required
    assert "evidence" in required
    assert "limitations" in required


@pytest.mark.parametrize("field", ["manifest", "evidence", "limitations"])
def test_removing_required_field_fails_schema(field: str) -> None:
    payload = copy.deepcopy(load_golden_report())
    del payload[field]
    with pytest.raises(ValidationError):
        CanonicalReport.model_validate(payload)
    with pytest.raises(Exception, match="required"):
        Draft202012Validator(_schema()).validate(payload)


def test_unknown_field_is_rejected() -> None:
    payload = copy.deepcopy(load_golden_report())
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        CanonicalReport.model_validate(payload)
    with pytest.raises(Exception, match="additional"):
        Draft202012Validator(_schema()).validate(payload)


def test_schema_version_literal() -> None:
    payload = copy.deepcopy(load_golden_report())
    payload["schema_version"] = "v0"
    with pytest.raises(ValidationError):
        CanonicalReport.model_validate(payload)
