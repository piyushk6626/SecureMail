---
status: current
audience: operator
authoritative_for: filesystem backup of data root and catalog
last_verified: 2026-09-06
---

# Backup and recovery

There is no dump API, no object store, and no database. Backup is a
filesystem copy of the roots you configured.

## What to copy

While Uvicorn and the worker are **stopped**:

1. Entire `SECUREMAIL_DATA_ROOT` (jobs, quarantine, `ml_history/`).
2. Entire `SECUREMAIL_REPORT_ROOT` if it is a different directory
   (`catalog.json` and `*.report.json`).
3. Optional CLI outputs (`out/*.json`, `out/certificates/`) if you rely on
   them.
4. Repository pins you already have in git: `tools/analyzer-bundle.lock`,
   policy YAML, trust-store PEM, IANA snapshot. Analyzer **images** are not
   in git; `docker save` them separately if the host must be rebuilt. See
   [air-gapped operation](air-gapped-operation.md).

Do not copy through symlinks that the job store would reject on read
(`O_NOFOLLOW`). Copy the real directories.

## Restore

1. Stop API and worker.
2. Replace the roots with the backup trees. Permissions: job dirs `0700`,
   status files regular files (not symlinks).
3. Confirm `catalog.json` parses as `securemail.report-catalog/v1`.
4. Start **one** Uvicorn with `SECUREMAIL_START_WORKER=1` (or one standalone
   worker).
5. `GET /api/v1/cases` should list restored case ids. `GET /api/v1/health`
   only proves the process is up.

Jobs left `running` in the backup are still `running` after restore. They
are **not** claimed again. Apply the stuck-job procedure in
[troubleshooting](troubleshooting.md).

## What backup does not include

- Docker image layers (Zeek base digest, `securemail/zeek:step0`,
  `securemail/tshark:step0`)
- Homebrew Pango / uv virtualenv / Node modules
- In-flight `quarantine/*.part` uploads (abort and re-upload)

## Integrity

Published `report.json` is RFC 8785. The CLI also writes
`report.json.sha256` beside artifacts it renders. Job-store artifacts do not
automatically write a sidecar `.sha256` file; the bytes in
`jobs/{run_id}/artifacts/report.json` are the canonical object.

## Related pages

- [Storage layout](storage-layout.md)
- [Retention and cleanup](retention-and-cleanup.md)
- [Air-gapped operation](air-gapped-operation.md)

## Implementation anchors

- `src/securemail/adapters/persistence/job_store.py`
- `src/securemail/adapters/persistence/writable_catalog.py`

## Test evidence

- `tests/unit/test_job_store.py` (`test_job_survives_store_reopen`)
- `tests/unit/test_canonical_json.py`
