"""EvidenceState and v0 document contract."""

from hypothesis import given
from hypothesis import strategies as st

from securemail.domain.evidence import (
    NORMALIZATION_SCHEMA_VERSION,
    AnalysisRun,
    CapturePreflight,
    EvidenceDocument,
    EvidenceState,
)


def test_evidence_state_has_seven_values() -> None:
    assert [state.value for state in EvidenceState] == [
        "observed",
        "verified",
        "inferred",
        "incomplete",
        "conflicting",
        "not_observable",
        "indeterminate",
    ]


@given(st.sampled_from(list(EvidenceState)))
def test_evidence_state_round_trips(state: EvidenceState) -> None:
    assert EvidenceState(state.value) is state


def test_v0_document_requires_run_identity_fields() -> None:
    document = EvidenceDocument(
        schema_version="v0",
        run_identity=AnalysisRun(
            capture_sha256="a" * 64,
            analyzer_bundle_digest="b" * 64,
            normalization_schema_version=NORMALIZATION_SCHEMA_VERSION,
            configuration_digest="c" * 64,
            policy_pack_version=None,
            trust_store_digest=None,
        ),
        capture_preflight=CapturePreflight(
            packet_count=0,
            file_time_precision="microsecond",
            truncated_packets_present=False,
        ),
        flows=[],
    )
    payload = document.model_dump(mode="json")
    identity = payload["run_identity"]
    assert identity["analyzer_bundle_digest"] == "b" * 64
    assert identity["capture_sha256"] == "a" * 64
    assert identity["normalization_schema_version"] == "v0"
    assert identity["policy_pack_version"] is None
    assert identity["trust_store_digest"] is None
    assert payload["sessions"] == []
