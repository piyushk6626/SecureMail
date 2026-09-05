---
status: current
audience: operator
authoritative_for: HTTP routes, status codes, and request shapes
last_verified: 2026-09-06
---

# HTTP API reference

FastAPI app factory: [`src/securemail/api/main.py`](../../src/securemail/api/main.py).
Uvicorn entry: `securemail.api.main:app`. OpenAPI is served by FastAPI at
`/docs` and `/openapi.json` when the app is running.

Routers are thin. Business logic lives in `application/` use cases.

There is **no authentication, authorization, or TLS termination**. Bind to
loopback on a trusted workstation. See
[security hardening](../operations/security-hardening.md).

All responses set:

- `Cache-Control: no-store`
- `Content-Security-Policy` (`default-src 'self'`, `object-src 'none'`,
  `frame-ancestors 'none'`)
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- `Referrer-Policy: no-referrer`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`

## Routes

| Method | Path | Success | Notes |
|---|---|---|---|
| `GET` | `/api/v1/health` | 200 | `{"status":"ok"}`. Liveness only; does not check Docker, disk, worker, or catalog. |
| `GET` | `/api/v1/cases` | 200 | Catalog summaries. 503 if the catalog is unreadable. |
| `GET` | `/api/v1/cases/{case_id}/report` | 200 | RFC 8785 canonical JSON. 404 if missing. |
| `GET` | `/api/v1/cases/{case_id}/report.html` | 200 | Rendered HTML attachment. |
| `GET` | `/api/v1/cases/{case_id}/report.pdf` | 200 | Rendered PDF attachment. |
| `POST` | `/api/v1/reports/preview` | 200 | Browser-local preview. Body is report JSON, max 8 MiB. 400 invalid, 413 too large. |
| `POST` | `/api/v1/analyses` | 202 | Multipart capture upload. 400 bad capture, 413 too large, 503 quota or analysis not configured. |
| `GET` | `/api/v1/analyses/{run_id}` | 200 | Job status JSON. 404 unknown run. |
| `POST` | `/api/v1/analyses/{run_id}/cancel` | 200 | Cooperative cancel. 409 if already terminal. |
| `GET` | `/api/v1/analyses/{run_id}/report` | 200 | Job JSON attachment. 409 if artifacts are not ready. |
| `GET` | `/api/v1/analyses/{run_id}/report.html` | 200 | Job HTML attachment. |
| `GET` | `/api/v1/analyses/{run_id}/report.pdf` | 200 | Job PDF attachment. |

`{case_id}` and `{run_id}`: 1–160 characters matching
`^[A-Za-z0-9][A-Za-z0-9._-]*$`.

When `SECUREMAIL_DATA_ROOT` / `SECUREMAIL_REPORT_ROOT` is unset, capture
routes return 503 `capture analysis is not configured`.

## `POST /api/v1/analyses`

Multipart form:

| Field | Required | Notes |
|---|---|---|
| `file` | yes | `.pcap` / `.pcapng`; magic must match the extension |
| `policy_profile` | no | Default `ietf_current` |
| `expected_hostname` | no | RFC 9525 configured identity |
| `case_id` | no | Optional caller-supplied case id |

Response is `AnalysisStatusView` JSON (202). Duplicate capture hashes reuse a
queued/running job.

```bash
curl -F file=@tests/fixtures/empty/capture.pcapng \
  -F policy_profile=ietf_current \
  http://127.0.0.1:8000/api/v1/analyses
```

## Job status view

| Field | Meaning |
|---|---|
| `run_id` / `case_id` | Identifiers |
| `status` | `queued`, `running`, `completed`, `failed`, `cancelled` |
| `stage` | `intake`, `deterministic_analysis`, `policy_scoring`, `ml_advisory`, `report_rendering`, `publication` |
| `capture_sha256` | Set after intake |
| `artifacts` | `{json, html, pdf}` booleans |
| `cancel_requested` | Cooperative cancel flag |
| `error_message` | Present on failure, max 1000 characters |

## Related pages

- [Environment variables](environment-variables.md)
- [API and worker startup](../operations/api-and-worker-startup.md)
- [Dashboard workflows](../user-guide/dashboard-workflows.md)
- [Monitoring and health](../operations/monitoring-and-health.md)

## Implementation anchors

- `src/securemail/api/routers/reports.py`
- `src/securemail/api/routers/analyses.py`
- `src/securemail/application/analysis_queries.py`
- `src/securemail/application/capture_intake.py`

## Test evidence

- `tests/test_report_api.py`
- `tests/test_analysis_api.py`
- `tests/test_capture_acceptance.py`
