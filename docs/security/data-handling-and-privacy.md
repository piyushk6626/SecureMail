---
status: current
audience: security
authoritative_for: what data is stored, hashed, redacted, and not fetched
last_verified: 2026-09-06
---

# Data handling and privacy

SecureMail is offline/on-premise. Enrichment is imported, hashed, timestamped,
and retained as evidence. Analyzers run `--network=none`. There is no AIA,
OCSP, CRL, CT, DNS, MTA-STS, model, or telemetry fetch from an analysis
worker.

## Hashing and originals

- Intake SHA-256 is `capture_sha256` **before** any analyzer runs.
- Do not repair evidential originals. Analyze working copies.
- CLI writes certificate DER under `<out-parent>/certificates/<sha256>.der`.
- **Known limitation:** the dashboard worker calls analyze **without**
  `artifact_root`, so it does not persist those DER files the way the CLI
  does. DER hashes still appear in evidence JSON.

## What is stored locally

| Location | Contents |
|---|---|
| `--out` JSON | Pretty `EvidenceDocument` |
| CLI `certificates/` | Content-addressed DER |
| Data root `jobs/` | Capture copy, status, HTML/PDF/JSON artifacts |
| Data root `quarantine/` | Staging during upload |
| Report root | `{case_id}.report.json` + `catalog.json` (max 256) |
| `ml_history/` | Bounded JSONL endpoint-windows (512) |

There is **no** retention API. Operators delete directories by hand. See
[operations — retention](../operations/retention-and-cleanup.md).

Quota accounting can **double-count** a staged upload during commit because
usage sums jobs **plus** quarantine, then adds `staged.stat().st_size` again.
ML history and catalog reports are not fully included in the 2 GiB data-root
cap.

## Redaction and logging

Protocol event arguments/text for secret commands are `<redacted>`. Do not
log payloads, credentials, private keys, or unnecessary PII.

HTML/PDF/UI escape decoded content. Canonical JSON keeps original (bounded)
strings so the forensic object remains honest; presentation filters make
controls and bidi visible.

## Identity in reports

SNI and `--expected-hostname` are used for RFC 9525 matching. Raw IPs and
serials must not be used as supervised ML features. Advisory reasons cite
canonical field paths, not “anomaly detected”.

## Related pages

- [Untrusted input handling](untrusted-input-handling.md)
- [Storage layout](../operations/storage-layout.md)
- [Current security limitations](current-security-limitations.md)

## Implementation anchors

- `src/securemail/application/run_analysis.py`
- `src/securemail/adapters/artifacts/certificate_store.py`
- `src/securemail/adapters/persistence/job_store.py`
- `src/securemail/bootstrap.py` (`_worker_analyze`)

## Test evidence

- `tests/unit/test_certificate_store.py`
- `tests/unit/test_job_store.py`
- `tests/unit/test_writable_catalog.py`
