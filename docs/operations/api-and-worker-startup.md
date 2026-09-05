---
status: current
audience: operator
authoritative_for: starting Uvicorn and the capture worker process
last_verified: 2026-09-06
---

# API and worker startup

Bind to loopback. There is no authentication. Do not use multiple Uvicorn
workers (`--workers` greater than 1 is **unsafe**: `claim_next()` is not
inter-process compare-and-swap).

Uvicorn entry: `securemail.api.main:app`. OpenAPI is served at `/docs` and
`/openapi.json` when the app is running (no auth).

Routes: [API reference](../reference/api.md).
Variables: [environment variables](../reference/environment-variables.md).

## Analysis workstation

```bash
uv sync --extra api --extra dev --extra reports --extra ml
```

Terminal 1:

```bash
SECUREMAIL_DATA_ROOT=out/data \
SECUREMAIL_REPORT_ROOT=out/data \
SECUREMAIL_START_WORKER=1 \
  uv run uvicorn securemail.api.main:app --host 127.0.0.1 --port 8000
```

`--reload` is optional for development. Reloading restarts the API process and
therefore terminates the lifespan worker.

Terminal 2:

```bash
npm --prefix frontend run dev
```

Vite listens on `127.0.0.1:5173` and proxies `/api` to `VITE_API_TARGET`
(default `http://127.0.0.1:8000`).

After `make frontend-build`, omit Vite; FastAPI serves `frontend/dist`.

## Catalog-only

```bash
SECUREMAIL_REPORT_ROOT=tests/fixtures/dashboard \
SECUREMAIL_START_WORKER=0 \
  uv run uvicorn securemail.api.main:app --host 127.0.0.1 --port 8000
```

Omitting `SECUREMAIL_START_WORKER=0` while a root is set **starts the
worker**.

## Worker process

The worker is `python -m securemail.worker`, which calls
`run_capture_worker_loop()`:

1. Requires `SECUREMAIL_DATA_ROOT` or `SECUREMAIL_REPORT_ROOT`.
2. Constructs `FilesystemJobStore`, `FilesystemMlHistoryStore`, and
   `FilesystemCatalogPublisher`.
3. Loops `process_next_job` then `time.sleep(0.5)`.
4. Runs one job at a time.
5. Uses `BaselineAnomalyScorer` and `IsolationForestScorer`.
6. Calls real `run_analysis` unless `SECUREMAIL_ANALYSIS_STUB=1`.

Lifespan startup (when `SECUREMAIL_START_WORKER=1`): `subprocess.Popen`
`[sys.executable, "-m", "securemail.worker"]` with the same data/report roots
copied into the child environment. On Darwin it prepends
`/opt/homebrew/lib` to `DYLD_FALLBACK_LIBRARY_PATH`. Shutdown: `terminate()`,
wait 15 s, then `kill()`.

You may start the worker **instead of** the lifespan flag, not in addition:

```bash
SECUREMAIL_DATA_ROOT=out/data \
SECUREMAIL_REPORT_ROOT=out/data \
  uv run python -m securemail.worker
```

Docker analyzers never run inside a FastAPI request or Starlette
`BackgroundTasks`.

## Smoke check

```bash
curl -s http://127.0.0.1:8000/api/v1/health
```

Expected body: `{"status":"ok"}`. This does not prove the worker, Docker, or
disk is healthy. See [monitoring and health](monitoring-and-health.md).

Upload proof (worker must be running):

```bash
curl -F file=@tests/fixtures/empty/capture.pcapng \
  -F policy_profile=ietf_current \
  http://127.0.0.1:8000/api/v1/analyses
```

Expect 202 and a `run_id`. Poll `GET /api/v1/analyses/{run_id}`.

## Related pages

- [Deployment topologies](deployment-topologies.md)
- [Job lifecycle](job-lifecycle.md)
- [Troubleshooting](troubleshooting.md)
- [First dashboard run](../getting-started/first-dashboard-run.md)

## Implementation anchors

- `src/securemail/api/main.py`
- `src/securemail/worker.py`
- `src/securemail/bootstrap.py` (`run_capture_worker_loop`, `create_api`)

## Test evidence

- `tests/test_report_api.py` (`test_uvicorn_app_entrypoint_imports_in_a_fresh_interpreter`)
- `tests/test_analysis_api.py`
- `tests/test_capture_acceptance.py`
