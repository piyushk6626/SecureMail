---
status: current
audience: operator
authoritative_for: environment variables and defaults
last_verified: 2026-09-06
---

# Environment variables

Nothing automatically loads [`.env.example`](../../.env.example). Export
variables in the shell, systemd unit, or process supervisor. Relative paths
resolve against the process working directory.

## Live variables

| Variable | Default | Effect |
|---|---|---|
| `DYLD_FALLBACK_LIBRARY_PATH` | Makefile sets `/opt/homebrew/lib` on Darwin | Lets the uv interpreter load Homebrew Pango/Cairo for PDF. |
| `SECUREMAIL_REPORT_ROOT` | unset | Canonical-report catalog directory. If only this is set, it also becomes the data root. |
| `SECUREMAIL_DATA_ROOT` | falls back to `SECUREMAIL_REPORT_ROOT` | Jobs, quarantine, artifacts, ML history. |
| `SECUREMAIL_START_WORKER` | `1` when either root is set, else `0` | Exactly `1` starts `python -m securemail.worker` from FastAPI lifespan. |
| `SECUREMAIL_ANALYSIS_STUB` | unset | Exactly `1` bypasses Docker. Tests and Playwright only. |
| `SECUREMAIL_MAX_CAPTURE_BYTES` | `67108864` (64 MiB) | Upload-byte cap. |
| `SECUREMAIL_CI` | unset | Doctor formatting in GitHub Actions. |
| `VITE_API_TARGET` | `http://127.0.0.1:8000` | Frontend Vite proxy target. |

Invalid `SECUREMAIL_MAX_CAPTURE_BYTES` is caught during `create_api()` and
**silently replaced** with the 64 MiB default (`CaptureIntakeError` is swallowed
in [`bootstrap.create_api`](../../src/securemail/bootstrap.py)). The CLI intake
path raises instead.

## Catalog-only vs analysis

```bash
# Catalog browse. Explicitly disable the worker.
SECUREMAIL_REPORT_ROOT=tests/fixtures/dashboard \
SECUREMAIL_START_WORKER=0 \
  uv run uvicorn securemail.api.main:app --reload
```

If `SECUREMAIL_START_WORKER` is omitted while a root is set, the worker
**starts**. Catalog-only docs that omit `SECUREMAIL_START_WORKER=0` are wrong.

```bash
# Analysis on this host
SECUREMAIL_DATA_ROOT=out/data \
SECUREMAIL_REPORT_ROOT=out/data \
SECUREMAIL_START_WORKER=1 \
  uv run uvicorn securemail.api.main:app --reload
```

## Unused placeholders

`DATABASE_URL` and `OIDC_ISSUER` are **not read**. They appeared in older
design notes. Do not configure them expecting a database or identity provider.

The `api` extra still lists SQLAlchemy, asyncpg, and Alembic. Those packages
are unused remnants, not a live control plane.

## Related pages

- [Configuration](../operations/configuration.md)
- [API and worker startup](../operations/api-and-worker-startup.md)
- [Limits](limits.md)

## Implementation anchors

- `src/securemail/bootstrap.py`
- `src/securemail/api/main.py`
- `src/securemail/application/capture_intake.py`
- `frontend/playwright.config.ts`

## Test evidence

- `tests/test_analysis_api.py`
- `tests/test_report_api.py`
