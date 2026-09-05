---
status: current
audience: operator
authoritative_for: on-disk data-root and report-root layout
last_verified: 2026-09-06
---

# Storage layout

`SECUREMAIL_DATA_ROOT` holds jobs, quarantine, and ML history.
`SECUREMAIL_REPORT_ROOT` is the canonical-report catalog (defaults to the
data root when unset).

Paths are generated from trusted ids matching
`^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$`. Original filenames are metadata only
(max 255 characters, basename only). Symlinks, `..`, and absolute catalog
paths are rejected.

```text
{data_root}/
  quarantine/{upload_id}.part
  jobs/{run_id}/
    status.json
    capture.pcap | capture.pcapng
    cancel.flag          # present when cancel is requested
    artifacts/
      report.json
      report.html
      report.pdf
  ml_history/windows.jsonl
{report_root}/
  catalog.json
  {case_id}.report.json
```

`upload_id` is `u` plus 16 hex characters. `run_id` is `r` plus 16 hex
characters unless a caller supplied `case_id` (case ids are separate from
run ids). Auto-generated `case_id` is `{cleaned-stem}-{first 8 of sha256}`.

Job directories are mode `0o700`. Quarantine files are created `0o600` with
`O_EXCL` and `O_NOFOLLOW` when the platform supports it.

## What lives where

| Path | Role |
|---|---|
| `quarantine/*.part` | Streaming upload before magic/hash commit. Aborted on validation failure. |
| `jobs/{run_id}/status.json` | Frozen `AnalysisJob` JSON (pretty, sorted keys). |
| `jobs/{run_id}/capture.*` | Stored capture after `os.replace` from quarantine. |
| `jobs/{run_id}/cancel.flag` | Contents `1\n` when cancel requested. |
| `jobs/{run_id}/artifacts/` | RFC 8785 JSON, HTML, PDF after rendering. Caps 8 / 16 / 32 MiB. |
| `ml_history/windows.jsonl` | Append-only derived endpoint windows; last 512 retained. |
| `catalog.json` | `schema_version: securemail.report-catalog/v1`, max 1 MiB, max 256 entries. |
| `{case_id}.report.json` | Published canonical JSON (atomic replace). |

Quota accounting for the 2 GiB data-root cap walks **jobs + quarantine
files only**. ML history and catalog reports at the report root are **not**
fully included. See [limits](../reference/limits.md)
(**known limitation**).

The 64-job cap counts **all** job directories, including completed, failed,
and cancelled. It is not a concurrent-job cap.

CLI `analyze --out` writes evidence JSON and
`<out-parent>/certificates/<sha256>.der` beside that path. Those files are
not under `data_root` unless you pointed `--out` there.

## Related pages

- [Job lifecycle](job-lifecycle.md)
- [Retention and cleanup](retention-and-cleanup.md)
- [Backup and recovery](backup-and-recovery.md)
- [Limits](../reference/limits.md)

## Implementation anchors

- `src/securemail/adapters/persistence/job_store.py`
- `src/securemail/adapters/persistence/report_repository.py`
- `src/securemail/adapters/persistence/writable_catalog.py`
- `src/securemail/adapters/persistence/ml_history_store.py`

## Test evidence

- `tests/unit/test_job_store.py`
- `tests/unit/test_report_repository.py`
- `tests/unit/test_capture_intake.py`
