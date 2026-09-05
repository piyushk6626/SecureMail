---
status: current
audience: operator
authoritative_for: manual job and catalog cleanup with no deletion API
last_verified: 2026-09-06
---

# Retention and cleanup

There is **no** deletion HTTP API and no TTL sweeper. Completed jobs stay on
disk until an operator removes directories. The 64-job cap counts every job
directory still present.

Stop the worker and Uvicorn before deleting files that a running claim might
touch.

## Jobs

Manual cleanup target: `{data_root}/jobs/{run_id}/`.

Each directory holds `status.json`, the capture, optional `cancel.flag`, and
`artifacts/`. Removing it frees one slot toward `MAX_JOB_COUNT` (64) and the
bytes toward the 2 GiB jobs+quarantine usage.

Do not delete a `running` job directory while a worker still holds it. Mark
it failed or requeue first ([troubleshooting](troubleshooting.md)), then
delete after the process is stopped.

Quarantine leftovers: `{data_root}/quarantine/*.part`. Intake aborts should
unlink these; stray parts still count toward the 2 GiB walk.

## Catalog

`{report_root}/catalog.json` plus `{case_id}.report.json`. Republishing the
same `case_id` replaces the report file and updates the catalog entry
(sorted by `case_id`). Exceeding 256 entries raises on publish; the job then
fails.

There is no prune helper. To drop cases, stop the API, edit `catalog.json` to
remove entries, delete the corresponding `{case_id}.report.json` files, and
keep `schema_version` `securemail.report-catalog/v1`. Invalid catalog JSON
makes `GET /api/v1/cases` return 503.

## ML history

`{data_root}/ml_history/windows.jsonl` retains at most 512 windows (oldest
dropped on append). Deleting this file resets advisory history; the next
runs emit `ADVISORY_INSUFFICIENT_HISTORY` until 14 windows accumulate again.
This file is **not** fully counted in the 2 GiB quota.

## CLI analyze outputs

`analyze --out` JSON and `certificates/*.der` are outside the job store.
Operators manage those paths themselves.

## Related pages

- [Storage layout](storage-layout.md)
- [Resource limits](resource-limits.md)
- [Backup and recovery](backup-and-recovery.md)
- [Limits](../reference/limits.md)

## Implementation anchors

- `src/securemail/adapters/persistence/job_store.py`
- `src/securemail/adapters/persistence/writable_catalog.py`
- `src/securemail/domain/jobs/models.py`

## Test evidence

- `tests/unit/test_job_store.py` (`test_job_count_quota`)
- `tests/unit/test_report_repository.py`
