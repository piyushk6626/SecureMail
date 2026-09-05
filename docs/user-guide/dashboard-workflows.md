---
status: current
audience: user
authoritative_for: dashboard analyst workflows and four-region case isolation
last_verified: 2026-09-06
---

# Dashboard workflows

The dashboard is FastAPI plus a React console over `securemail.report/v1`. It
can browse a catalog and upload `.pcap` / `.pcapng` on one trusted
workstation. Packet decoding still happens in sandboxed Zeek and TShark, never
in the browser.

There is **no login**. Bind to loopback. See
[security hardening](../operations/security-hardening.md).

Startup commands: [first dashboard run](../getting-started/first-dashboard-run.md)
and [API and worker startup](../operations/api-and-worker-startup.md). Route
tables: [API reference](../reference/api.md).

## Sources

- Server catalog (`SECUREMAIL_REPORT_ROOT`): `{case_id}.report.json` named by
  `catalog.json`.
- Captures analyzed on this host (`SECUREMAIL_DATA_ROOT`): jobs, quarantine,
  ML history, published reports.

Every report fetch names a case or analysis run explicitly. There is no
implicit current/latest report.

## No case selected

The main pane shows **No case selected** (`data-testid="no-case-selected"`)
until you pick a catalog case or upload a capture. Clearing a selection
removes prior evidence from the view (React Query cache for case-report,
analysis, and analysis-report is dropped). The empty state must not leak
another case’s facts, findings, or notes.

Portfolio view lists catalog summaries (risk, finding count, unknown +
not-observable) without loading full evidence. Opening a case loads that
case’s report only.

## Four labeled regions

The case view keeps these separate:

1. **Observed Facts** — flow / session / handshake / certificate counts,
   certificate validity/identity tallies, frame-linked event text.
2. **Deterministic Conclusions** — scored findings table (search, severity,
   evidence-state filters). Unknown/incomplete/indeterminate/not-observable
   stay labeled.
3. **Advisory / ML** — shadow-mode items. Until 14 local endpoint-windows
   exist, expect `ADVISORY_INSUFFICIENT_HISTORY`. ML never changes findings.
4. **Analyst Notes** — read-only notes from the canonical report. Worker
   assembly publishes an empty section in this build.

Hostile strings render as forensic text, with control and bidirectional
characters made visible.

HTML and PDF downloads appear after a run completes, and for catalog cases.

## Capture upload

Primary intake is `.pcap` / `.pcapng`. Magic bytes must match the extension.
The API streams the file to quarantine, hashes it, and enqueues a job. A
dedicated worker (`python -m securemail.worker`) runs analyze, assembles a
canonical report, scores advisory ML against local history, and publishes
JSON/HTML/PDF.

The UI dropzone sends `policy_profile=ietf_current`. It does not expose a
profile picker or `--expected-hostname`. Use curl for those form fields
([API reference](../reference/api.md)).

Default upload cap is 64 MiB
([limits](../reference/limits.md),
[environment variables](../reference/environment-variables.md)).

Duplicate `(capture_sha256, policy_profile, expected_hostname)` reuses a
queued, running, or completed job instead of creating a second run. Failed or
cancelled jobs are not reused.

Polling: `GET /api/v1/analyses/{run_id}` every 1 s while `queued` or
`running`. Stages, in order:

1. `intake`
2. `deterministic_analysis`
3. `policy_scoring`
4. `ml_advisory`
5. `report_rendering`
6. `publication`

Cancel is cooperative between stages. It does not kill a running Docker
analyzer. Queued jobs become `cancelled` immediately. Terminal jobs return
409.

Failed and cancelled jobs show an empty state with the error message (max
1000 characters) or a cancelled note. They do not display another case.

Until 14 (baseline) / 40 (Isolation Forest) endpoint-windows exist locally,
Advisory / ML shows `ADVISORY_INSUFFICIENT_HISTORY` rather than implying that
no anomaly was found.

## Header health pill

“API online” means `GET /api/v1/health` returned `{"status":"ok"}`. That
endpoint is **liveness only**. It does not check Docker, disk, the worker, or
the catalog. A green pill with a stuck job or missing analyzer image is
expected. See [monitoring and health](../operations/monitoring-and-health.md).

## Production static UI

After `make frontend-build`, FastAPI serves `frontend/dist` from the same
Uvicorn process. Vite `npm --prefix frontend run dev` listens on
`127.0.0.1:5173` and proxies `/api` to `VITE_API_TARGET`
(default `http://127.0.0.1:8000`).

## Related pages

- [First dashboard run](../getting-started/first-dashboard-run.md)
- [Advisory ML](advisory-ml.md)
- [Generate reports](generate-reports.md)
- [API reference](../reference/api.md)
- [Job lifecycle](../operations/job-lifecycle.md)
- [API reference](../reference/api.md)

## Implementation anchors

- `frontend/src/App.tsx`
- `frontend/src/components/case_view.tsx`
- `src/securemail/api/main.py`
- `src/securemail/application/analysis_workflow.py`

## Test evidence

- `tests/e2e/dashboard.spec.ts`
- `tests/test_report_api.py`
- `tests/test_analysis_api.py`
- `tests/test_capture_acceptance.py`
