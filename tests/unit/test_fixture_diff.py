"""Field-level JSON diffs for the fixture harness."""

from tests.support.fixture_harness import diff_json


def test_diff_json_reports_missing_and_changed_fields() -> None:
    expected = {"run_identity": {"capture_sha256": "aa", "nested": {"x": 1}}}
    actual = {"run_identity": {"capture_sha256": "bb", "nested": {"x": 1}, "extra": True}}
    diffs = diff_json(expected, actual)
    assert "$.run_identity.capture_sha256: 'aa' != 'bb'" in diffs
    assert "$.run_identity.extra: unexpected in actual" in diffs


def test_diff_json_equal_documents() -> None:
    payload = {"schema_version": "v0", "run_identity": {"capture_sha256": "aa"}}
    assert diff_json(payload, payload) == []
