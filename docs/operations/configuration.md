---
status: current
audience: operator
authoritative_for: how operators set roots, worker, and upload caps
last_verified: 2026-09-06
---

# Configuration

Nothing automatically loads `.env.example`. Export variables in the shell or
process supervisor. Relative paths resolve against the process working
directory.

Canonical table: [environment variables](../reference/environment-variables.md).
Do not duplicate that table here.

## Catalog-only vs analysis

```bash
# Catalog browse. Explicitly disable the worker.
SECUREMAIL_REPORT_ROOT=tests/fixtures/dashboard \
SECUREMAIL_START_WORKER=0 \
  uv run uvicorn securemail.api.main:app --host 127.0.0.1 --port 8000
```

```bash
# Analysis on this host
SECUREMAIL_DATA_ROOT=out/data \
SECUREMAIL_REPORT_ROOT=out/data \
SECUREMAIL_START_WORKER=1 \
  uv run uvicorn securemail.api.main:app --host 127.0.0.1 --port 8000
```

`SECUREMAIL_START_WORKER` defaults to `1` when either root is set, else `0`.
Exactly `1` starts `python -m securemail.worker` from FastAPI lifespan.

`SECUREMAIL_DATA_ROOT` falls back to `SECUREMAIL_REPORT_ROOT`. If only the
report root is set, jobs and ML history are created **there** unless the
worker is disabled.

When neither root is set, `create_api()` uses a sentinel unconfigured path
and `job_store` is `None`. Capture routes then return 503
`capture analysis is not configured`.

**Known limitation:** `SECUREMAIL_START_WORKER=0` does not disable upload
routes. If a root is set, `FilesystemJobStore` is still constructed and
`POST /api/v1/analyses` can enqueue jobs into that tree with nobody to
claim them (or into a fixture catalog directory). Catalog-only hosts should
not expose the dropzone to operators who might upload. Use a dedicated
writable `SECUREMAIL_DATA_ROOT` for analysis.

## Upload cap

`SECUREMAIL_MAX_CAPTURE_BYTES` defaults to 64 MiB (`MAX_CAPTURE_BYTES`).
Invalid values are caught during `create_api()` and **silently replaced**
with 64 MiB (`CaptureIntakeError` is swallowed in `bootstrap.create_api`).
The CLI intake helper `env_max_capture_bytes()` raises instead.

## macOS PDF libraries

On Darwin the Makefile exports `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`.
The API lifespan prepends the same path when starting the worker so WeasyPrint
can load Homebrew Pango. Do not `brew install weasyprint`.

## Stub analysis

`SECUREMAIL_ANALYSIS_STUB=1` bypasses Docker and runs `stub_analyze`. It is
for tests and Playwright (`frontend/playwright.config.ts` sets it). Do not
enable it on a workstation that is supposed to decode real captures.

## Unused placeholders

`DATABASE_URL` and `OIDC_ISSUER` are **not read**. The `api` extra still lists
SQLAlchemy, asyncpg, and Alembic; those packages are unused remnants, not a
live control plane.

Frontend proxy: `VITE_API_TARGET` (default `http://127.0.0.1:8000`).

`SECUREMAIL_CI=1` only changes doctor formatting in GitHub Actions.

## Related pages

- [Environment variables](../reference/environment-variables.md)
- [API and worker startup](api-and-worker-startup.md)
- [Deployment topologies](deployment-topologies.md)

## Implementation anchors

- `src/securemail/bootstrap.py`
- `src/securemail/api/main.py`
- `src/securemail/application/capture_intake.py`

## Test evidence

- `tests/test_analysis_api.py`
- `tests/test_report_api.py`
