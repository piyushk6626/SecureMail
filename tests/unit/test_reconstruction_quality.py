"""Pure reconstruction-quality classification (Step 1)."""

from securemail.domain.evidence.flow import (
    ByteRange,
    ObservedCondition,
    ReconstructionFacts,
    ReconstructionQuality,
    ReconstructionReasonCode,
    StreamDirection,
    classify_reconstruction,
)
from securemail.domain.evidence.run import EvidenceState


def _facts(**overrides: object) -> ReconstructionFacts:
    base: dict[str, object] = {
        "proto": "tcp",
        "history": "ShADadFf",
        "conn_state": "SF",
        "missed_bytes": 0,
        "orig_bytes": 64,
        "resp_bytes": 64,
        "weird_names": (),
        "capture_loss_gaps": 0,
        "truncated_packets": False,
        "gap_ranges": (),
        "conflicting_ranges": (),
        "retransmission_count": 0,
        "out_of_order": False,
        "duplicate_segments": False,
    }
    base.update(overrides)
    return ReconstructionFacts(**base)  # type: ignore[arg-type]


def test_complete_clean_handshake() -> None:
    verdict = classify_reconstruction(_facts())
    assert verdict.reconstruction_quality is ReconstructionQuality.COMPLETE
    assert verdict.reason_code is None
    assert verdict.gap_bytes == 0
    assert verdict.gap_bytes_exact is True
    assert verdict.observed_conditions == []
    assert verdict.evidence_state is EvidenceState.OBSERVED


def test_out_of_order_remains_complete() -> None:
    verdict = classify_reconstruction(_facts(out_of_order=True))
    assert verdict.reconstruction_quality is ReconstructionQuality.COMPLETE
    assert verdict.reason_code is None
    assert verdict.observed_conditions == [ObservedCondition.OUT_OF_ORDER_SEGMENTS]


def test_duplicate_segments_remain_complete() -> None:
    verdict = classify_reconstruction(_facts(duplicate_segments=True, retransmission_count=1))
    assert verdict.reconstruction_quality is ReconstructionQuality.COMPLETE
    assert verdict.reason_code is None
    assert verdict.observed_conditions == [ObservedCondition.DUPLICATE_SEGMENTS]


def test_missing_syn() -> None:
    verdict = classify_reconstruction(_facts(history="ADadFf", conn_state="OTH"))
    assert verdict.reconstruction_quality is ReconstructionQuality.INCOMPLETE
    assert verdict.reason_code is ReconstructionReasonCode.MISSING_SYN
    assert verdict.gap_bytes == 0
    assert verdict.evidence_state is EvidenceState.INCOMPLETE


def test_missing_fin() -> None:
    verdict = classify_reconstruction(_facts(history="ShADad", conn_state="S1"))
    assert verdict.reconstruction_quality is ReconstructionQuality.INCOMPLETE
    assert verdict.reason_code is ReconstructionReasonCode.MISSING_FIN
    assert verdict.gap_bytes == 0


def test_midstream_start_from_prefix_gap() -> None:
    gap = ByteRange(start=1, end=65, direction=StreamDirection.ORIG, exact=True)
    verdict = classify_reconstruction(_facts(missed_bytes=64, gap_ranges=(gap,)))
    assert verdict.reconstruction_quality is ReconstructionQuality.INCOMPLETE
    assert verdict.reason_code is ReconstructionReasonCode.MIDSTREAM_START
    assert verdict.gap_bytes == 64
    assert verdict.gap_bytes_exact is True


def test_segment_gap_after_handshake() -> None:
    gap = ByteRange(start=80, end=100, direction=StreamDirection.ORIG, exact=True)
    verdict = classify_reconstruction(_facts(missed_bytes=20, gap_ranges=(gap,)))
    assert verdict.reason_code is ReconstructionReasonCode.SEGMENT_GAP
    assert verdict.gap_bytes == 20


def test_overlapping_conflict_outranks_truncation() -> None:
    conflict = ByteRange(start=51, end=201, direction=StreamDirection.ORIG, exact=True)
    verdict = classify_reconstruction(
        _facts(truncated_packets=True, missed_bytes=10, conflicting_ranges=(conflict,))
    )
    assert verdict.reconstruction_quality is ReconstructionQuality.CONFLICTING
    assert verdict.reason_code is ReconstructionReasonCode.OVERLAPPING_RETRANSMISSION_CONFLICT
    assert verdict.conflicting_byte_ranges == [conflict]
    assert verdict.gap_bytes == 0
    assert ObservedCondition.DUPLICATE_SEGMENTS not in verdict.observed_conditions


def test_capture_loss() -> None:
    verdict = classify_reconstruction(
        _facts(capture_loss_gaps=3, missed_bytes=0, orig_bytes=0, resp_bytes=0)
    )
    assert verdict.reason_code is ReconstructionReasonCode.CAPTURE_LOSS
    assert verdict.gap_bytes_exact is False


def test_unknown_gap_range_is_not_invented() -> None:
    gap = ByteRange(start=0, end=0, direction=StreamDirection.ORIG, exact=False)
    verdict = classify_reconstruction(_facts(history="ADad", conn_state="OTH", gap_ranges=(gap,)))
    assert verdict.reason_code is ReconstructionReasonCode.MIDSTREAM_START
    assert verdict.gap_bytes_exact is False


def test_non_tcp_complete_unless_truncated() -> None:
    verdict = classify_reconstruction(_facts(proto="udp", history="D", conn_state="S0"))
    assert verdict.reconstruction_quality is ReconstructionQuality.COMPLETE
    truncated = classify_reconstruction(
        _facts(proto="udp", history="D", conn_state="S0", truncated_packets=True)
    )
    assert truncated.reason_code is ReconstructionReasonCode.SNAPLEN_TRUNCATION


def test_rejected_syn_rst_is_complete() -> None:
    verdict = classify_reconstruction(
        _facts(history="Sr", conn_state="REJ", orig_bytes=0, resp_bytes=0)
    )
    assert verdict.reconstruction_quality is ReconstructionQuality.COMPLETE
