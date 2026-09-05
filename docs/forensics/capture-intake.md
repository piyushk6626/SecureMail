---
status: current
audience: architect
authoritative_for: PCAP/PCAPNG magic validation, hashing before analyzers, and API quarantine intake
last_verified: 2026-09-06
---

# Capture intake

Intake proves the file is a capture, hashes the **original bytes**, and only
then allows analyzers to read a working copy. Analyzers never rewrite the
intake file. The SHA-256 of those bytes becomes
`run_identity.capture_sha256` and is part of the run idempotency tuple.

CLI `securemail analyze` and HTTP `POST /api/v1/analyses` share the magic
constants. They do **not** share the size cap, filename rules, or quarantine
path.

## Inputs

| Path | Input |
|---|---|
| CLI | Filesystem path to an existing file. Extension is not required. |
| API | Multipart upload whose basename ends in `.pcap` or `.pcapng`. |
| Both | First four bytes of the file (magic). |
| API only | `policy_profile`, optional `expected_hostname`, optional `case_id`. |
| API only | Byte cap `MAX_CAPTURE_BYTES` (64 MiB default; `SECUREMAIL_MAX_CAPTURE_BYTES`). |

Numeric caps: [limits](../reference/limits.md). Environment override:
[environment variables](../reference/environment-variables.md).

## Outputs

| Output | Where |
|---|---|
| `capture_sha256` | `EvidenceDocument.run_identity` (CLI) and `AnalysisJob.capture_sha256` (API) |
| Reject | CLI exit 1 / `InvalidCaptureError`; API HTTP 400 or 413 |
| Staged file | API: `{data-root}/quarantine/{upload_id}.part` then `{data-root}/jobs/{run_id}/capture.{pcap\|pcapng}` |
| Preflight | After hash: capinfos inside the TShark image produces `CapturePreflight` |

Capinfos is not magic validation. It runs **after** the hash, in a
network-disabled sandbox, and records packet count, snaplen / inferred
limits, `truncated_packets_present`, duration, and `capture_start_time`.

## Evidence states

Intake itself does not emit `EvidenceState`. Failures are hard errors, not
`incomplete` flows. After a successful intake:

- `truncated_packets_present` is a **capture-wide** boolean copied onto every
  flow as `ReconstructionFacts.truncated_packets`.
- `historical_at_capture` policy requires `capture_start_time`. Missing that
  timestamp is a policy-engine error, not a silent pass.

## Precedence rules

Magic check, then hash, then analyzers. Never the reverse.

### Magic bytes

Read the first four bytes:

| Format | Bytes |
|---|---|
| PCAPNG | `0a 0d 0d 0a` |
| PCAP little-endian microsecond | `d4 c3 b2 a1` |
| PCAP big-endian microsecond | `a1 b2 c3 d4` |
| PCAP little-endian nanosecond | `4d 3c b2 a1` |
| PCAP big-endian nanosecond | `a1 b2 3c 4d` |

Anything else is `InvalidCaptureError` (“not a PCAP/PCAPNG file”).

### CLI vs API

1. **CLI** (`run_analysis`): path must be a file. Magic is checked. SHA-256
   of the whole file is computed. Capinfos and Zeek then receive that same
   path bind-mounted read-only. Filename extension is ignored.
2. **API** (`ingest_capture`): basename is stripped of path components.
   Extension selects expected format (`pcapng` vs `pcap`). Bytes stream into
   a quarantine `.part` while hashing. After the stream ends, the first four
   bytes must match **that** format’s magic (extension/magic mismatch is
   rejected). Empty uploads are rejected. Oversize uploads raise
   `CaptureTooLargeError` (HTTP 413).

Duplicate API intakes that share `(capture_sha256, policy_profile,
expected_hostname)` reuse the prior job when that job is still non-terminal
**or** already `completed`. Failed and cancelled jobs are not reused.

## Uncertainty behavior

- A truncated or empty file that still starts with valid magic is accepted
  at intake. Later stages record `incomplete` reconstruction or empty
  sessions. The Step 0 `empty` fixture is a valid PCAPNG with no mail.
- Capinfos may omit `capture_start_time`. The document still serializes;
  `historical_at_capture` then fails closed.
- CLI does **not** enforce the 64 MiB API cap. A huge local file can still
  fail later on analyzer timeout (120 s) or the 50 MiB combined analyzer
  output bound.
- `truncated_packets_present=true` does not mean “this flow was truncated.”
  It means **some** packet in the file had captured length less than original
  length. The TCP classifier applies that flag to every flow.

## Security bounds

Treat the capture as hostile.

| Bound | Value | Notes |
|---|---|---|
| API upload | 64 MiB default | Counted while streaming; abort deletes the `.part` |
| Original filename | 255 characters | Path components stripped; only the basename is stored |
| Quarantine create | `O_CREAT\|O_EXCL`, mode `0o600` | No follow of symlinks when `O_NOFOLLOW` exists |
| Job / quarantine dirs | mode `0o700` | Under the configured data root |
| Analyzer bind | read-only at `/data/capture.pcapng` | `--network=none`, non-root `65532` |
| Hash | SHA-256 of original bytes | Before Zeek, TShark, or capinfos |

API `case_id` must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$`. If omitted,
intake derives one from the cleaned filename stem plus the first eight hex
characters of the digest.

Packet payloads, credentials, and message bodies are not written at intake.
They are also not written later; see [protocol identification](protocol-identification.md)
redaction.

Sandbox isolation (not intake hashing) is documented in
[analyzer boundary](../architecture/analyzer-boundary.md).

## Fixture examples

| Case | What intake proves |
|---|---|
| `empty` | Valid PCAPNG magic; stable `capture_sha256`; byte-identical rerun |
| `tcp_snaplen_truncation` | Magic accepted; `truncated_packets_present=true` on preflight |
| Unit `test_capture_intake.py` | Extension/magic mismatch rejected; oversize rejected; `.part` cleaned on abort; path in filename stripped |

Proof:

```bash
uv run securemail analyze tests/fixtures/empty/capture.pcapng --out /tmp/empty.json
```

## Limitations

- **Known limitation:** CLI `analyze` does not apply `MAX_CAPTURE_BYTES`.
  Only the HTTP intake path does.
- **Known limitation:** CLI does not require a `.pcap` / `.pcapng` suffix.
  API does, and additionally requires magic to match that suffix.
- **Known limitation:** quota accounting can double-count a staged upload
  during commit. See [known limitations](../status/known-limitations.md).
- **Unsupported:** formats other than PCAP and PCAPNG (snoop, netmon, raw
  sockets).
- **Deferred:** streaming analysis that starts Zeek before the last byte
  arrives. The whole file is hashed first.

## Related pages

- [Forensic pipeline](README.md)
- [TCP reconstruction](tcp-reconstruction.md)
- [Analysis pipeline](../architecture/analysis-pipeline.md)
- [Limits](../reference/limits.md)
- [Untrusted input handling](../security/untrusted-input-handling.md)

## Implementation anchors

- `src/securemail/application/run_analysis.py` (`PCAPNG_MAGIC`, `PCAP_MAGICS`, `sha256_file`)
- `src/securemail/application/capture_intake.py`
- `src/securemail/adapters/persistence/job_store.py` (`stage_capture`, `commit_staged`)
- `src/securemail/api/routers/analyses.py`
- `src/securemail/domain/jobs/models.py` (`MAX_CAPTURE_BYTES`)
- `src/securemail/adapters/analyzers/capinfos_runner.py`

## Test evidence

- `tests/unit/test_capture_intake.py`
- `tests/unit/test_job_store.py`
- `tests/unit/test_run_analysis.py`
- `tests/fixtures/empty/`
