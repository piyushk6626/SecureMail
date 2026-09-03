"""Named Step 1 exit criterion: truncation is never reported complete."""

from securemail.domain.evidence.flow import (
    ReconstructionFacts,
    ReconstructionQuality,
    ReconstructionReasonCode,
    classify_reconstruction,
)
from securemail.domain.evidence.run import EvidenceState


def test_truncated_stream_never_reported_complete() -> None:
    """A truncated stream must never be silently reported as complete.

    Byte counts that look smaller are not enough; the quality field itself
    must be incomplete with reason snaplen_truncation even when Zeek reports
    missed_bytes=0 and a tidy handshake history.
    """

    verdict = classify_reconstruction(
        ReconstructionFacts(
            proto="tcp",
            history="ShADadFf",
            conn_state="SF",
            missed_bytes=0,
            orig_bytes=64,
            resp_bytes=64,
            weird_names=(),
            capture_loss_gaps=0,
            truncated_packets=True,
            gap_ranges=(),
            conflicting_ranges=(),
            retransmission_count=0,
            out_of_order=False,
            duplicate_segments=False,
        )
    )
    assert verdict.reconstruction_quality is not ReconstructionQuality.COMPLETE
    assert verdict.reconstruction_quality is ReconstructionQuality.INCOMPLETE
    assert verdict.reason_code is ReconstructionReasonCode.SNAPLEN_TRUNCATION
    assert verdict.evidence_state is EvidenceState.INCOMPLETE
    assert verdict.gap_bytes_exact is False
