"""Step 1 TCP reconstruction fixtures through the real CLI path."""

from __future__ import annotations

import json

import pytest
from tests.support.fixture_harness import repo_root, run_fixture

from securemail.domain.evidence.flow import ReconstructionQuality, ReconstructionReasonCode

STEP1_CASES = (
    "tcp_smtp_clean_baseline",
    "tcp_missing_syn",
    "tcp_missing_fin",
    "tcp_midstream_start",
    "tcp_snaplen_truncation",
    "tcp_overlapping_retransmission_conflict",
    "tcp_out_of_order_segments",
    "tcp_duplicate_segments",
)

_DEGRADED_QUALITY = {
    "tcp_missing_syn": ReconstructionQuality.INCOMPLETE,
    "tcp_missing_fin": ReconstructionQuality.INCOMPLETE,
    "tcp_midstream_start": ReconstructionQuality.INCOMPLETE,
    "tcp_snaplen_truncation": ReconstructionQuality.INCOMPLETE,
    "tcp_overlapping_retransmission_conflict": ReconstructionQuality.CONFLICTING,
}

_DEGRADED_REASON = {
    "tcp_missing_syn": ReconstructionReasonCode.MISSING_SYN,
    "tcp_missing_fin": ReconstructionReasonCode.MISSING_FIN,
    "tcp_midstream_start": ReconstructionReasonCode.MIDSTREAM_START,
    "tcp_snaplen_truncation": ReconstructionReasonCode.SNAPLEN_TRUNCATION,
    "tcp_overlapping_retransmission_conflict": (
        ReconstructionReasonCode.OVERLAPPING_RETRANSMISSION_CONFLICT
    ),
}


@pytest.mark.parametrize("case_id", STEP1_CASES)
def test_tcp_fixture_matches_expected_json(case_id: str) -> None:
    run_fixture(case_id)


def test_snaplen_fixture_expected_is_never_complete() -> None:
    """Independent of incidental byte-count checks in the golden document."""

    expected_path = repo_root() / "tests" / "fixtures" / "tcp_snaplen_truncation" / "expected.json"
    payload = json.loads(expected_path.read_text(encoding="utf-8"))
    tcp_flows = [flow for flow in payload["flows"] if flow["proto"] == "tcp"]
    assert tcp_flows, "snaplen fixture must contain a TCP flow"
    for flow in tcp_flows:
        assert flow["reconstruction_quality"] != ReconstructionQuality.COMPLETE
        assert flow["reason_code"] == ReconstructionReasonCode.SNAPLEN_TRUNCATION


def test_degraded_expected_documents_name_reasons() -> None:
    root = repo_root()
    for case_id, quality in _DEGRADED_QUALITY.items():
        payload = json.loads((root / "tests" / "fixtures" / case_id / "expected.json").read_text())
        tcp_flows = [flow for flow in payload["flows"] if flow["proto"] == "tcp"]
        assert tcp_flows
        assert any(flow["reconstruction_quality"] == quality for flow in tcp_flows)
        assert any(flow["reason_code"] == _DEGRADED_REASON[case_id] for flow in tcp_flows)


def test_recoverable_expected_documents_stay_complete() -> None:
    root = repo_root()
    for case_id, condition in (
        ("tcp_out_of_order_segments", "out_of_order_segments"),
        ("tcp_duplicate_segments", "duplicate_segments"),
    ):
        payload = json.loads((root / "tests" / "fixtures" / case_id / "expected.json").read_text())
        tcp_flows = [flow for flow in payload["flows"] if flow["proto"] == "tcp"]
        assert tcp_flows
        assert all(
            flow["reconstruction_quality"] == ReconstructionQuality.COMPLETE for flow in tcp_flows
        )
        assert any(condition in flow["observed_conditions"] for flow in tcp_flows)


def test_clean_baseline_expected_is_complete() -> None:
    path = repo_root() / "tests" / "fixtures" / "tcp_smtp_clean_baseline" / "expected.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    tcp_flows = [flow for flow in payload["flows"] if flow["proto"] == "tcp"]
    assert tcp_flows
    assert all(
        flow["reconstruction_quality"] == ReconstructionQuality.COMPLETE for flow in tcp_flows
    )
    assert all(flow["gap_bytes"] == 0 for flow in tcp_flows)
