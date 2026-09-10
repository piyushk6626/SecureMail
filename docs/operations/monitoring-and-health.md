---
status: current
audience: operator
authoritative_for: health endpoint semantics and what is not monitored
last_verified: 2026-09-09
---

# Monitoring and health

`GET /api/v1/health` always returns HTTP 200 `{"status":"ok"}`. It is
**liveness only**. It does not check Docker, disk quota, the worker process,
analyzer image digests, Pango, or catalog readability.

The dashboard does not display that probe. A 200 from `/api/v1/health` with
failed jobs or a dead worker is still expected.

FastAPI OpenAPI at `/docs` is also unauthenticated. Do not treat it as a
health dashboard.

## What you can probe yourself

| Check | How | Healthy sign |
|---|---|---|
| API process | `curl -s http://127.0.0.1:8000/api/v1/health` | `{"status":"ok"}` |
| Catalog | `curl -s http://127.0.0.1:8000/api/v1/cases` | 200 JSON list; 503 if catalog unreadable |
| Worker | process list for `python -m securemail.worker`; job `status.json` advancing | stages change; not stuck `running` with no worker |
| Docker | `docker info`; `docker image inspect securemail/zeek:step0 securemail/tshark:step0` | daemon up; local tags present |
| Doctor | `make doctor` | all lines pass |

There are no metrics exporters, log shippers, or readiness vs liveness
split in this build (**deferred** in historical design).

## Job observation

`GET /api/v1/analyses/{run_id}` returns status, stage, `cancel_requested`,
artifact flags, and `error_message`. Poll while `queued` or `running`. The
UI polls every 1 s.

Host logs: Uvicorn stdout plus worker stdout/stderr (same terminal when
started via lifespan). Analyzer stderr is captured inside the runner and
surfaced as `AnalyzerExecutionError` / job `error_message` (last 2000
characters of analyzer stderr on non-zero exit).

## Related pages

- [API reference](../reference/api.md)
- [Troubleshooting](troubleshooting.md)
- [API and worker startup](api-and-worker-startup.md)

## Implementation anchors

- `src/securemail/api/routers/reports.py` (`health`)
- `frontend/src/App.tsx` (health query)
- `tools/doctor.py`

## Test evidence

- `tests/test_report_api.py`
- `tests/e2e/dashboard.spec.ts`
