"""EvidenceState and v1 document contract."""

from datetime import UTC, datetime

from hypothesis import given
from hypothesis import strategies as st

from securemail.domain.evidence import (
    NORMALIZATION_SCHEMA_VERSION,
    AnalysisRun,
    CapturePreflight,
    CertificateValidation,
    EvidenceDocument,
    EvidenceState,
    PolicyProfile,
    ReferenceIdentitySource,
    RevocationStatus,
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


def test_v1_document_requires_run_identity_fields() -> None:
    analysis_time = datetime(2026, 9, 4, 12, tzinfo=UTC)
    document = EvidenceDocument(
        schema_version="v1",
        run_identity=AnalysisRun(
            capture_sha256="a" * 64,
            analyzer_bundle_digest="b" * 64,
            normalization_schema_version=NORMALIZATION_SCHEMA_VERSION,
            configuration_digest="c" * 64,
            analysis_time=analysis_time,
            policy_profile=PolicyProfile.IETF_CURRENT,
            policy_pack_version="d" * 64,
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
    assert identity["normalization_schema_version"] == "v1"
    assert identity["policy_pack_version"] == "d" * 64
    assert identity["policy_profile"] == "ietf_current"
    assert identity["analysis_time"] == "2026-09-04T12:00:00Z"
    assert identity["trust_store_digest"] is None
    assert payload["sessions"] == []
    assert payload["handshakes"] == []
    assert payload["certificates"] == []
    assert payload["findings"] == []
    assert payload["capture_preflight"]["capture_start_time"] is None


def test_certificate_validation_serializes_leaf_contract() -> None:
    validation = CertificateValidation(
        certificate_observed=True,
        syntax_valid=True,
        path_valid_at_capture_time=True,
        path_valid_at_analysis_time=False,
        path_invalid_reasons_at_analysis_time=["expired_at_verification_time"],
        identity_match=False,
        identity_mismatch_reasons=["san_mismatch"],
        reference_identity="wrong.example.test",
        reference_identity_source=ReferenceIdentitySource.SNI,
        revocation_status=RevocationStatus.UNKNOWN,
        trust_profile_id="offline_v1",
        trust_store_digest="a" * 64,
    )
    payload = validation.model_dump(mode="json")
    assert payload["path_valid_at_capture_time"] is True
    assert payload["path_valid_at_analysis_time"] is False
    assert payload["identity_match"] is False
    assert payload["revocation_status"] == "unknown"
    assert payload["reference_identity_source"] == "sni"
    assert payload["trust_store_digest"] == "a" * 64
