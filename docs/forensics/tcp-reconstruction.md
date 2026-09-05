---
status: current
audience: architect
authoritative_for: TCP reconstruction quality classification and reason-code precedence
last_verified: 2026-09-06
---

# TCP reconstruction

Python does not reassemble TCP. Zeek’s standard reassembly runs inside the
sandbox. Python classifies **quality** from `conn.log`, `capture_loss.log`,
preflight snaplen facts, and the custom `sm_tcp_recon.log`.

A truncated stream is never reported `complete` with a smaller byte count
and no state. Missing evidence is `incomplete` or `conflicting`, never a
silent pass.

## Inputs

| Source | Facts used |
|---|---|
| `conn.log` | `uid`, endpoints, `proto`, `history`, `conn_state`, `missed_bytes`, `orig_bytes`, `resp_bytes` |
| `weird.log` | Names joined onto the flow (not the primary quality driver) |
| `capture_loss.log` | Sum of `gaps` across rows → `capture_loss_gaps` |
| `sm_tcp_recon.log` | `seq_gap`, `out_of_order`, `duplicate`, `overlap`, `rexmit`, `rexmit_inconsistency` |
| `CapturePreflight` | `truncated_packets_present` copied onto **every** flow |

Normalizer: `normalize_flows`. Pure classifier: `classify_reconstruction`.

## Outputs

Each `Flow` carries a reconstruction verdict flattened onto the record:

| Field | Values |
|---|---|
| `reconstruction_quality` | `complete`, `incomplete`, `conflicting` |
| `reason_code` | Set when quality is not complete |
| `observed_conditions` | Recoverable `out_of_order_segments` / `duplicate_segments` |
| `gap_bytes` / `gap_bytes_exact` | Count of missing bytes; `false` when the count is not known exactly |
| `conflicting_byte_ranges` | Half-open `[start, end)` in relative TCP sequence space |
| `evidence_state` | Mapped from quality |

Non-TCP flows (`udp`, `icmp`, `icmp6`, `unknown`) are `complete` unless the
capture has truncated packets.

## Evidence states

| `reconstruction_quality` | `evidence_state` | Meaning |
|---|---|---|
| `complete` | `observed` | Stream usable; recoverable reorder/duplicate may still be listed |
| `incomplete` | `incomplete` | Missing SYN/FIN, midstream, snaplen, gaps, or capture loss |
| `conflicting` | `conflicting` | Overlapping retransmission with disagreeing bytes |

`not_observable` is not used on `Flow.evidence_state`. A connection that Zeek
logged is observed at the transport layer even if application bytes are
missing.

See [evidence states](../reference/evidence-states.md).

## Precedence rules

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

### Reason codes

| Code | Typical fixture |
|---|---|
| `missing_syn` | `tcp_missing_syn` |
| `missing_fin` | `tcp_missing_fin` |
| `midstream_start` | `tcp_midstream_start` |
| `snaplen_truncation` | `tcp_snaplen_truncation` |
| `overlapping_retransmission_conflict` | `tcp_overlapping_retransmission_conflict` |
| `segment_gap` | Unresolved gap after a SYN (no dedicated fixture name beyond gap handling) |
| `capture_loss` | From `capture_loss.log` `gaps` |

### Zeek history letters used

The classifier inspects `conn.log` `history` only for these tests:

- originator SYN: `S`
- responder SYN-ACK: `h`
- FIN: `F` or `f`
- RST: `R` or `r`
- data: `D` or `d`
- ACK (establishment without data): `A`

### `sm_tcp_recon.log` → facts

`zeek/scripts/tcp-reconstruction.zeek` tracks expected next sequence per UID
and direction. `tcp_max_old_segments = 8`.

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

## Uncertainty behavior

- Never invent `gap_bytes` when the count is unknown: set
  `gap_bytes_exact=false` (snaplen with no missed_bytes, capture-loss gaps).
- Capture-wide snaplen truncation degrades **every** TCP flow once precedence
  reaches that check (after conflicts). A mixed capture that contains any
  truncated packet therefore classifies TCP flows as snaplen-incomplete.
- Later TLS/session stages inherit transport uncertainty: a conflicting flow
  makes the handshake `evidence_state=conflicting`; selected incomplete
  reasons without `established` make the handshake `incomplete`.
- Downstream policy must not treat `incomplete` reconstruction as “no
  weakness detected.”

## Security bounds

| Bound | Value |
|---|---|
| Zeek / TShark rows | 10 000 each |
| Reconstruction events per flow | 256 |
| UID / host | 64 / 253 characters |
| `history` | 256 characters |
| Analyzer sandbox | `--network=none`, read-only capture mount |
| Logged recon facts | Sequence numbers and lengths only — **never payload bytes** |

Do not repair evidential originals. Competing reconstructions are represented
only as `conflicting` quality plus `conflicting_byte_ranges`, not as
alternative stream objects.

## Fixture examples

| Case | Quality | Extra |
|---|---|---|
| `tcp_smtp_clean_baseline` | `complete`, `gap_bytes=0` | Lab SMTP |
| `tcp_out_of_order_segments` | `complete` | `observed_conditions` includes `out_of_order_segments` |
| `tcp_duplicate_segments` | `complete` | `observed_conditions` includes `duplicate_segments` |
| `tcp_missing_syn` / `_fin` / `_midstream_start` / `_snaplen_truncation` | `incomplete` | matching `reason_code` |
| `tcp_overlapping_retransmission_conflict` | `conflicting` | `overlapping_retransmission_conflict` |

The `tcp_snaplen_truncation` fixture is a single truncated SMTP stream:
`missed_bytes=128`, `gap_bytes=128`, `gap_bytes_exact=true`.

Proof:

```bash
uv run securemail analyze tests/fixtures/tcp_snaplen_truncation/capture.pcapng
```

## Limitations

- **Implemented:** quality classification from Zeek metadata; recoverable
  reorder/duplicate recorded without degrading `complete`.
- **Known limitation:** Python does not emit reconstructed payloads or
  alternative competing streams as first-class objects.
- **Known limitation:** `truncated_packets_present` is capture-wide, so one
  truncated packet marks every TCP flow snaplen-incomplete after conflicts.
- **Unsupported:** UDP reassembly, HTTP, or non-mail application streams as
  email sessions.
- **Deferred:** publishing two competing reconstructions when bytes disagree.

## Related pages

- [Capture intake](capture-intake.md)
- [Protocol identification](protocol-identification.md)
- [Evidence states](../reference/evidence-states.md)
- [Analyzer boundary](../architecture/analyzer-boundary.md)

## Implementation anchors

- `src/securemail/domain/evidence/flow.py` (`classify_reconstruction`)
- `src/securemail/application/normalize_flows.py`
- `zeek/scripts/tcp-reconstruction.zeek`

## Test evidence

- `tests/test_tcp_fixtures.py`
- `tests/unit/test_reconstruction_quality.py`
- `tests/unit/test_truncated_stream_never_complete.py`
- `tests/unit/test_normalize_flows.py`
