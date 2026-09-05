---
status: current
audience: operator
authoritative_for: operator implications of numeric caps
last_verified: 2026-09-06
---

# Resource limits

Values below are from source constants. They are not tuned from benchmarks.
The canonical table is [limits](../reference/limits.md). This page is what
those numbers mean on a workstation.

## Jobs and catalog

| Cap | Operator effect |
|---|---|
| 64 MiB upload | HTTP 413. Overridable via `SECUREMAIL_MAX_CAPTURE_BYTES` (invalid API values silently fall back to 64 MiB). |
| 64 job directories | Counts **all** retained jobs (queued, running, completed, failed, cancelled). New uploads 503 when full. Not a concurrency cap. |
| 2 GiB data root | Jobs + quarantine file sizes. ML history and catalog JSON are **not** fully counted (**known limitation**). |
| 256 catalog reports | Publish fails if `catalog.json` would exceed 256 entries. |
| 8 / 16 / 32 MiB | Canonical JSON / HTML / PDF artifacts. Worker fails the job if HTML or PDF exceeds the cap. |
| 512 ML windows | Oldest dropped from `windows.jsonl`. |
| 8 MiB | CLI `score` and `report` inputs; HTTP report preview. |

**Known limitation:** quota accounting can double-count a staged upload during
commit. `max_jobs` is not concurrent-job capacity.

## Analyzers (Docker)

Capinfos, Zeek, and optional TShark run **sequentially**, 120 s each. Worst
case analyzer time approaches **360 seconds** before report rendering.

Each container: `--network=none`, `--read-only`, user `65532:65532`,
`--cap-drop=ALL`, `no-new-privileges`, `--pids-limit=256`, `--memory=2g`,
`--memory-swap=2g`, `--cpus=2`, `/tmp` tmpfs 64 MiB. Combined analyzer output
50 MiB; certificate DER 64 KiB each, 256 per run.

**Known limitation:** TShark uses `subprocess.run(capture_output=True)` and
checks size afterward. Zeek may `read_bytes()` a log before rejecting it.
Documented output limits bound accepted data, not peak host allocation during
collection.

WeasyPrint and ML run in the **host worker**. They do **not** inherit Docker
memory/CPU limits.

## Worker process

| Cap | Value |
|---|---|
| Poll | 0.5 s |
| Concurrency | one job at a time |
| Cancel | between stages; does not kill a running analyzer |

Multiple Uvicorn or worker processes are **unsafe**.

## Normalization / policy bounds

See the remainder of [limits](../reference/limits.md) (Zeek rows, policy pack
size, trust store, IANA snapshot). Those protect parsers; they are not
throughput knobs.

## Related pages

- [Limits](../reference/limits.md)
- [Performance and tuning](performance-and-tuning.md)
- [Retention and cleanup](retention-and-cleanup.md)

## Implementation anchors

- `src/securemail/domain/jobs/models.py`
- `src/securemail/adapters/analyzers/sandbox.py`
- `src/securemail/ports/persistence.py`

## Test evidence

- `tests/unit/test_capture_intake.py`
- `tests/unit/test_job_store.py`
- `tests/unit/test_report_repository.py`
