---
status: current
audience: architect
authoritative_for: local out-of-process worker versus Celery
last_verified: 2026-09-06
---

# 0003. Local worker model

Date: 2026-09-06 (retrospective)
Status: accepted
Step: post-11 capture dashboard

## Question

Should capture analysis run in the FastAPI request, in Celery/RabbitMQ
workers, or in a dedicated local process?

## Decision

Run analysis **out of process** via `python -m securemail.worker`. FastAPI
lifespan may start that process when `SECUREMAIL_START_WORKER=1`. The loop
calls `process_next_job` then `time.sleep(0.5)`.

Celery, RabbitMQ, Redis, and multi-queue workers remain **Deferred**.
Analysis does **not** execute inside a FastAPI request handler.

## Why

- Zeek/TShark can take up to 120 s each (sequential with capinfos). Holding
  an HTTP worker that long is unsafe.
- A single-host product does not need a broker.
- The same `run_analysis` use case serves CLI and worker.

## Consequences

- **Known limitation:** `claim_next()` is not compare-and-swap. Two worker
  processes can claim the same job. The model is **not multi-process safe**.
- Cancel is cooperative between stages; it does not kill a running analyzer
  subprocess. A dead worker leaves jobs `running`.
- Poll interval 0.5 s is a source constant, not a tuned SLA.
- Stub mode (`SECUREMAIL_ANALYSIS_STUB=1`) is for tests and Playwright only.

## Related pages

- [Known limitations](../status/known-limitations.md)
- [Environment variables](../reference/environment-variables.md)
- [Future scale-out](../future/scale-out-control-plane.md)

## Implementation anchors

- `src/securemail/worker.py`
- `src/securemail/bootstrap.py` (`run_capture_worker_loop`)
- `src/securemail/application/analysis_workflow.py`
- `src/securemail/adapters/persistence/job_store.py`

## Test evidence

- `tests/unit/test_analysis_workflow.py`
- `tests/test_analysis_api.py`
- `frontend/playwright.config.ts` (`SECUREMAIL_ANALYSIS_STUB=1`)
