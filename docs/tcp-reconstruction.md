# TCP reconstruction

Python does not reassemble TCP. Zeek’s standard reassembly runs inside the
sandbox. Python classifies **quality** from `conn.log`, `capture_loss.log`,
preflight snaplen facts, and the custom `sm_tcp_recon.log`.

Pure function: `classify_reconstruction` in
[`src/securemail/domain/evidence/flow.py`](../src/securemail/domain/evidence/flow.py).
Normalizer: [`normalize_flows.py`](../src/securemail/application/normalize_flows.py).

## Quality vs evidence state

| `reconstruction_quality` | `evidence_state` | Meaning |
|---|---|---|
| `complete` | `observed` | Stream usable; recoverable reorder/duplicate may still be listed |
| `incomplete` | `incomplete` | Missing SYN/FIN, midstream, snaplen, gaps, or capture loss |
| `conflicting` | `conflicting` | Overlapping retransmission with disagreeing bytes |

A truncated stream is never reported `complete` with a smaller byte count and
no state. `tests/test_tcp_fixtures.py` asserts that independently of incidental
sizes.

## Classifier precedence

First matching rule wins:

1. **Non-TCP:** if the capture has truncated packets → `incomplete` /
   `snaplen_truncation` with `gap_bytes_exact=false`; else `complete`.
2. **Conflicting ranges** (from `rexmit_inconsistency` plus overlap/rexmit
   lengths) → `conflicting` / `overlapping_retransmission_conflict`.
3. **Truncated packets** (capture-wide preflight flag) → `incomplete` /
   `snaplen_truncation`. `gap_bytes` is `missed_bytes` if &gt; 0, else the sum
   of `seq_gap` ranges; `gap_bytes_exact` is true only when that count is &gt; 0.
4. **Unresolved gap** (`missed_bytes > 0` or `seq_gap` ranges) → `incomplete`.
   Reason is `midstream_start` if there is no originator SYN in `history` or a
   gap starts at relative sequence ≤ 1; otherwise `segment_gap`.
5. **Capture-loss gaps** (sum of `gaps` on all `capture_loss.log` rows) →
   `incomplete` / `capture_loss` with `gap_bytes_exact=false`.
6. **Missing originator SYN** (`S` absent from `history`) → `incomplete` /
   `missing_syn`.
7. **Established without FIN/RST** (SYN-ACK `h` or data `D`/`d` or ack `A`,
   and neither `F`/`f` nor `R`/`r`) → `incomplete` / `missing_fin`.
8. Else **complete**.

`observed_conditions` records `out_of_order_segments` and/or
`duplicate_segments` (duplicate events or `retransmission_count > 0`) **only
when quality is not conflicting**. They do not degrade a complete stream.

## Reason codes

| Code | Typical fixture |
|---|---|
| `missing_syn` | `tcp_missing_syn` |
| `missing_fin` | `tcp_missing_fin` |
| `midstream_start` | `tcp_midstream_start` |
| `snaplen_truncation` | `tcp_snaplen_truncation` |
| `overlapping_retransmission_conflict` | `tcp_overlapping_retransmission_conflict` |
| `segment_gap` | Unresolved gap after a SYN (no dedicated fixture name beyond gap handling) |
| `capture_loss` | From `capture_loss.log` `gaps` |

## Zeek history letters used

The classifier inspects `conn.log` `history` only for these tests:

- originator SYN: `S`
- responder SYN-ACK: `h`
- FIN: `F` or `f`
- RST: `R` or `r`
- data: `D` or `d`
- ACK (establishment without data): `A`

## `sm_tcp_recon.log` → facts

[`zeek/scripts/tcp-reconstruction.zeek`](../zeek/scripts/tcp-reconstruction.zeek)
tracks expected next sequence per UID and direction.

| `event_type` | Normalizer effect |
|---|---|
| `seq_gap` | `content_gap` → `gap_ranges` |
| `out_of_order` | `facts.out_of_order` |
| `duplicate` | segment entirely behind expected seq → `duplicate_segments` |
| `overlap` | partial overlap with already-acked data → overlap ranges |
| `rexmit` | `tcp_rexmit` → `retransmission_count` + ranges |
| `rexmit_inconsistency` | overlapping payload disagreement; length only, never `t1`/`t2` bytes → `conflicting_ranges` |

Payload arguments on `tcp_packet` are unused. `rexmit_inconsistency` logs
overlap length only.

If inconsistency is flagged: prefer overlap ranges, else rexmit ranges, else a
non-exact `[0, length)` range so the classifier can still return `conflicting`
without inventing sequence numbers.

## Preflight interaction

`CapturePreflight.truncated_packets_present` is copied onto **every** flow’s
`ReconstructionFacts.truncated_packets`. A mixed capture that contains any
snaplen-truncated packet therefore classifies TCP flows as snaplen-incomplete
once precedence reaches that check (and after conflicts). The
`tcp_snaplen_truncation` fixture is a single truncated SMTP stream:
`missed_bytes=128`, `gap_bytes=128`, `gap_bytes_exact=true`.

## Recoverable vs degraded fixtures

| Case | Quality | Extra |
|---|---|---|
| `tcp_smtp_clean_baseline` | `complete`, `gap_bytes=0` | Lab SMTP |
| `tcp_out_of_order_segments` | `complete` | `observed_conditions` includes `out_of_order_segments` |
| `tcp_duplicate_segments` | `complete` | `observed_conditions` includes `duplicate_segments` |
| `tcp_missing_syn` / `_fin` / `_midstream_start` / `_snaplen_truncation` | `incomplete` | matching `reason_code` |
| `tcp_overlapping_retransmission_conflict` | `conflicting` | `overlapping_retransmission_conflict` |

Proof command: `securemail analyze tests/fixtures/tcp_snaplen_truncation/capture.pcapng`.

## Not in this build

Python does not emit reconstructed payloads or alternative competing streams as
first-class objects. Competing reconstructions are represented only as
`conflicting` quality plus `conflicting_byte_ranges`. TLS handshake
completeness is Step 4.
