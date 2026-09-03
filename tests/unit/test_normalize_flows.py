"""Zeek log normalization into Flow records."""

from securemail.application.normalize_flows import normalize_flows
from securemail.domain.evidence.flow import ReconstructionQuality, ReconstructionReasonCode
from securemail.domain.evidence.run import CapturePreflight


def _preflight(*, truncated: bool = False) -> CapturePreflight:
    return CapturePreflight(
        packet_count=8,
        file_time_precision="microsecond",
        truncated_packets_present=truncated,
        original_packet_bytes=500,
        capture_duration_seconds=0.05,
    )


def test_normalize_skips_malformed_rows() -> None:
    logs: dict[str, list[dict[str, object]]] = {
        "conn.log": [
            {
                "uid": "ok1",
                "id.orig_h": "192.0.2.10",
                "id.orig_p": 1,
                "id.resp_h": "192.0.2.25",
                "id.resp_p": 25,
                "proto": "tcp",
                "history": "ShADadFf",
                "conn_state": "SF",
                "missed_bytes": 0,
            },
            {"uid": "bad", "id.orig_h": 1},
        ]
    }
    flows = normalize_flows(logs, _preflight())
    assert len(flows) == 1
    assert flows[0].uid == "ok1"
    assert flows[0].reconstruction_quality is ReconstructionQuality.COMPLETE


def test_normalize_joins_conflict_events() -> None:
    logs: dict[str, list[dict[str, object]]] = {
        "conn.log": [
            {
                "uid": "Cconflict",
                "id.orig_h": "192.0.2.10",
                "id.orig_p": 49152,
                "id.resp_h": "192.0.2.25",
                "id.resp_p": 25,
                "proto": "tcp",
                "history": "ShADadTFf",
                "conn_state": "SF",
                "missed_bytes": 0,
                "orig_bytes": 250,
                "resp_bytes": 0,
            }
        ],
        "sm_tcp_recon.log": [
            {
                "uid": "Cconflict",
                "event_type": "rexmit_inconsistency",
                "len": 150,
                "is_orig": True,
            },
            {
                "uid": "Cconflict",
                "event_type": "rexmit",
                "seq": 51,
                "len": 200,
                "is_orig": True,
                "range_start": 51,
                "range_end": 251,
            },
        ],
    }
    flows = normalize_flows(logs, _preflight())
    assert flows[0].reconstruction_quality is ReconstructionQuality.CONFLICTING
    assert flows[0].reason_code is ReconstructionReasonCode.OVERLAPPING_RETRANSMISSION_CONFLICT
    assert flows[0].conflicting_byte_ranges[0].start == 51
    assert flows[0].conflicting_byte_ranges[0].end == 251


def test_normalize_applies_truncation_from_preflight() -> None:
    logs: dict[str, list[dict[str, object]]] = {
        "conn.log": [
            {
                "uid": "Ctrunc",
                "id.orig_h": "192.0.2.10",
                "id.orig_p": 49152,
                "id.resp_h": "192.0.2.25",
                "id.resp_p": 25,
                "proto": "tcp",
                "history": "ShADadFf",
                "conn_state": "SF",
                "missed_bytes": 0,
            }
        ]
    }
    flows = normalize_flows(logs, _preflight(truncated=True))
    assert flows[0].reason_code is ReconstructionReasonCode.SNAPLEN_TRUNCATION
    assert flows[0].reconstruction_quality is ReconstructionQuality.INCOMPLETE
