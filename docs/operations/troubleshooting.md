---
status: current
audience: operator
authoritative_for: operator runbooks for stuck jobs, analyzers, catalog, quota, PDF, Docker, proxy, worker
last_verified: 2026-09-06
---

# Troubleshooting

Confirm `/health` only means the API process answered. It will stay `ok`
through every failure mode below.

## Stuck `running` jobs

**Symptom:** `GET /api/v1/analyses/{run_id}` stays `running`. Stage does not
advance. `/health` is still `ok`.

**Cause:** `claim_next()` only picks `queued` jobs. If the worker dies after
claim, or you restore a backup mid-run, the job remains `running` forever.
There is **no auto-requeue**. `execute_capture_job` returns immediately when
status is not `running`, so a restarted worker will not resume that id.

Also wait out sequential analyzers: up to 120 s × 3 (worst ~360 s) plus
unbounded host PDF/ML before calling it stuck.

**Procedure:**

1. Stop Uvicorn (this terminates a lifespan worker: SIGTERM, 15 s, then
   kill). Ensure no second `python -m securemail.worker` remains.
2. Confirm no leftover analyzer containers: `docker ps` (runners use
   `--rm`).
3. Read `{data_root}/jobs/{run_id}/status.json`.
4. Choose one:
   - **Abandon:** set `"status": "failed"` and a short `"error_message"`
     (max 1000 characters). Leave the directory until
     [retention](retention-and-cleanup.md) cleanup.
   - **Retry:** set `"status": "queued"`, `"cancel_requested": false`,
     `"stage": "intake"`. Delete `cancel.flag` if present. Do not change
     `run_id` or the capture file.
5. Start **exactly one** worker again
   (`SECUREMAIL_START_WORKER=1` **or** `uv run python -m securemail.worker`,
   not both).
6. Poll the run. Duplicate uploads of the same hash+profile+hostname will
   keep attaching to a `completed` job; they will not recover a `running`
   zombie until you finish this procedure.

Cancel of a live `running` job only sets `cancel.flag`. It does not kill
Docker. If the worker is already dead, cancel alone will not move the
status to `cancelled`.

## Analyzer digest mismatch

**Symptom:** CLI exit 1 or job `failed` with messages such as:

- `zeek/ bundle hash does not match tools/analyzer-bundle.lock`
- `TShark Dockerfile digest does not match tools/analyzer-bundle.lock`
- `Zeek image digest does not match the pinned zeek/zeek:8.0.10 digest`
- `securemail/zeek:step0 is missing; run make zeek-image`
- `securemail/tshark:step0 is missing; run make tshark-image`
- missing or mismatched `securemail.zeek_bundle_sha256` /
  `securemail.zeek_base_digest` labels

**Procedure:**

```bash
make doctor
make tshark-image
make zeek-image
```

If you changed `zeek/` or the TShark Dockerfile, regenerate the lock only
with `make analyzer-lock` and refresh fixtures as a development change — do
not hand-edit the lock. Pull the pinned Zeek base if inspect fails:

```bash
docker pull zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3
```

**Known limitation:** TShark is recipe-pinned (Dockerfile SHA-256), not
content-pinned. Rebuilding later can yield a different TShark binary. See
[toolchain](../reference/toolchain.md).

## Corrupt catalog

**Symptom:** `GET /api/v1/cases` → 503 `report catalog unavailable`. UI
shows “Catalog unavailable.”

**Causes:** `catalog.json` not valid JSON; wrong `schema_version` (must be
`securemail.report-catalog/v1`); more than 256 entries; duplicate case ids;
path traversal, symlink, missing file, non-`.json` entry; report over 8 MiB.

**Procedure:**

1. Stop the API.
2. Validate `{report_root}/catalog.json` by eye or `python -m json.tool`.
3. Each `reports[]` item: `case_id` matching the id alphabet, `report`
   relative `*.json` under the root (not `catalog.json` itself).
4. Restore from backup if the file is truncated.
5. Restart and retry `GET /api/v1/cases`.

Case fetch 404 is a missing id, not a corrupt catalog.

## Disk quota

**Symptom:** upload 503 `capture storage quota exceeded`.

**Causes:** 64 job directories already present (including completed), or
jobs+quarantine file sizes would exceed 2 GiB after the staged upload.

**Procedure:**

1. List `{data_root}/jobs/` — count directories.
2. Delete finished job directories you no longer need
   ([retention](retention-and-cleanup.md)).
3. Remove stray `{data_root}/quarantine/*.part`.
4. Remember ML history and catalog JSON may still grow outside the 2 GiB
   walk (**known limitation**).

There is no API to free space.

## Pango / PDF

**Symptom:** `securemail report --format pdf` or worker `report_rendering`
fails with WeasyPrint / Pango load errors, or
`PDF rendering requires the reports extra`.

**Procedure:**

```bash
uv sync --extra reports
```

macOS:

- `brew install pango` (not WeasyPrint)
- Export `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib` (Makefile does this
  for `make` targets; API lifespan prepends it for the worker)
- Intel `/usr/local` Homebrew is **unsupported**

Linux: install `libpango1.0-dev` and related libraries as in
[Linux setup](../getting-started/linux.md).

Doctor: Pango ≥ 1.58 via pkg-config.

JSON/HTML render without WeasyPrint. Request `--format json,html` if PDF is
optional.

## Docker down

**Symptom:** `AnalysisError` wrapping analyzer failures; `docker info`
fails; capinfos/Zeek/TShark cannot start.

**Procedure:**

```bash
docker info
make doctor
```

Start Docker Desktop / Engine. Rebuild local tags if inspect of
`securemail/zeek:step0` or `securemail/tshark:step0` fails:

```bash
make tshark-image
make zeek-image
```

CLI `analyze` and the worker both need the daemon. Catalog-only browse does
not.

`SECUREMAIL_ANALYSIS_STUB=1` hides this by skipping Docker — never use that
to “fix” production analysis.

## Frontend proxy

**Symptom:** UI “API unavailable”; browser calls to `/api/v1/health` fail;
uploads never reach FastAPI.

**Checks:**

1. Uvicorn actually bound to `127.0.0.1:8000` (or the port you chose).
2. Vite `VITE_API_TARGET` matches that origin (default
   `http://127.0.0.1:8000`). Playwright uses port **8011** and
   `VITE_API_TARGET=http://127.0.0.1:8011`.
3. `npm --prefix frontend run dev` is the process that proxies `/api`.
   Opening `frontend/dist` via a random static server will not proxy.
4. After `make frontend-build`, use the FastAPI origin directly so `/api`
   is same-origin.

CORS is not the design; the UI is same-origin via the proxy or the mounted
`dist`.

## Worker crash

**Symptom:** jobs remain `queued` (never claimed) or `running` (claimed then
died). API still returns `/health` ok. Lifespan child may have exited while
Uvicorn continued.

**Procedure:**

1. `ps` for `securemail.worker`. If missing and `SECUREMAIL_START_WORKER=1`,
   restart Uvicorn (lifespan starts a new child) **or** start
   `uv run python -m securemail.worker` with the same roots — not both.
2. Read worker/Uvicorn stderr for `AnalyzerError`, `PdfRenderError`,
   `MlDependencyError`, `ReportRepositoryError`.
3. `ml` extra missing → Isolation Forest raises `MlDependencyError` wrapped
   as `AdvisoryPipelineError` → job `failed`. Run
   `uv sync --extra ml --extra reports --extra api`.
4. Apply stuck-job recovery if status is `running`.
5. Confirm Docker and Pango as above.

Worker loops forever; a crash of the process is not retried by an internal
supervisor. Uvicorn does not restart a dead child until the API process
itself restarts.

## Capture rejected

| HTTP / CLI | Typical cause |
|---|---|
| 400 magic/extension | `.pcap` vs `.pcapng` mismatch; not a capture |
| 400 empty | zero-length upload |
| 413 | over `SECUREMAIL_MAX_CAPTURE_BYTES` |
| CLI exit 2 | missing path (Typer) |
| CLI exit 1 `not a PCAP/PCAPNG file` | magic check |
| CLI exit 1 historical | missing `capture_start_time` |

## Related pages

- [Job lifecycle](job-lifecycle.md)
- [API and worker startup](api-and-worker-startup.md)
- [Limits](../reference/limits.md)
- [Toolchain](../reference/toolchain.md)

## Implementation anchors

- `src/securemail/adapters/persistence/job_store.py`
- `src/securemail/adapters/analyzers/bundle_lock.py`
- `src/securemail/api/routers/analyses.py`
- `src/securemail/api/main.py`

## Test evidence

- `tests/unit/test_job_store.py`
- `tests/unit/test_bundle_lock.py`
- `tests/unit/test_capture_intake.py`
- `tests/unit/test_report_repository.py`
- `tests/unit/test_analysis_workflow.py`
