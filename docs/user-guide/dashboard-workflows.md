---
status: current
audience: user
authoritative_for: dashboard analyst workflows and four-region case isolation
last_verified: 2026-09-11
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

## Routes

| Path | View |
|---|---|
| `/` | Redirects to `/cases` |
| `/cases` | Catalog of published case summaries |
| `/cases/:case_id` | Case detail (four labeled regions) |
| `/upload` | Capture intake, progress, and terminal job errors |

The header shows the SecureMail logo (links to `/cases`) and **Upload
capture**. There is no sidebar, no API health pill, and no light theme.

The catalog lists summaries without loading full evidence: generated time,
assessment state, **Highest endpoint priority**, finding count, four severity
counts, separate unknown/not-observable counts, and advisory presence. A null
priority is **Not proven**, not a zero or healthy result. Cases are ordered by
scored priority, unresolved count, generated time, then case ID. Opening a
case loads that case’s report only.
**Back to catalog** returns to `/cases` and drops React Query caches for
case-report, analysis, and analysis-report so another case cannot leak into
the view (`data-testid="no-case-selected"` on the catalog page).

## Assessment trust and four labeled regions

Every case subview starts with **Assessment trust**. It shows the canonical
assessment state, **Highest endpoint priority (0–100)** or **Not proven**, the
four coverage outcomes, capture limitations, stage errors, and short/full run
provenance. A limited/none assessment or an evidence limitation opens the
limitations panel. **Acknowledge limits and continue** only changes the local
view; it does not turn unknown evidence into a pass.

The overview then shows an endpoint-first action tree and a 4 × 4 coverage
matrix. The matrix has SMTP, IMAP, POP3, and unclassified rows with transport,
mail-protocol, TLS-handshake, and certificate columns. Select a cell to see
the exact canonical policy checks behind it. Passed checks appear there; they
are not findings.

The case view keeps these separate:

1. **Observed Facts** — flow, session, handshake, and certificate records;
   selected STARTTLS/STLS timeline; frame-linked protocol and TLS messages.
   A port hint is not protocol proof; uncorrelated implicit TLS stays
   indeterminate.
2. **Deterministic Conclusions** — endpoint-first scored findings with
   remediation/rule/protocol grouping, searchable filters, a six-addend score
   explanation, occurrences, and evidence/frame lineage. Unknown,
   incomplete, indeterminate, and not-observable states stay labelled.
3. **Advisory / ML** — shadow-mode items. Until 14 local endpoint-windows
   exist, expect `ADVISORY_INSUFFICIENT_HISTORY`. Advisory never changes
   deterministic findings.
4. **Analyst Conclusions** — read-only notes from the canonical report. Worker
   assembly publishes an empty section in this build.

Hostile strings render as forensic text, with control and bidirectional
characters made visible.

Certificate path, SAN identity, capture-time validity, analysis-time validity,
and revocation are separate facts. Revocation is normally **unknown** in the
offline workflow; it is never shown as “not revoked.” A TLS 1.3 certificate
that cannot be observed is an unresolved visibility limit, not a healthy empty
certificate list.

HTML and PDF downloads appear after a run completes, and for catalog cases.

## Capture upload

Open `/upload` (header **Upload capture**). Primary intake is `.pcap` /
`.pcapng`. Magic bytes must match the extension. The API streams the file to
quarantine, hashes it, and enqueues a job. A dedicated worker
(`python -m securemail.worker`) runs analyze, assembles a canonical report,
scores advisory ML against local history, and publishes JSON/HTML/PDF.

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

When `status` is `completed`, the UI navigates to
`/cases/{case_id}?run={run_id}` so HTML/PDF links use job artifact URLs.
Failed and cancelled jobs stay on `/upload` with the error message (max 1000
characters) or a cancelled note. They do not display another case.

Until 14 (baseline) / 40 (Isolation Forest) endpoint-windows exist locally,
Advisory / ML shows `ADVISORY_INSUFFICIENT_HISTORY` rather than implying that
no anomaly was found.

## Health endpoint

`GET /api/v1/health` still returns `{"status":"ok"}` for process liveness. The
dashboard does not display that probe. See
[monitoring and health](../operations/monitoring-and-health.md).

## Production static UI

After `make frontend-build`, FastAPI serves `frontend/dist` from the same
Uvicorn process. Reloading `/cases`, `/cases/{case_id}`, or `/upload` returns
the SPA `index.html`. Vite `npm --prefix frontend run dev` listens on
`127.0.0.1:5173` and proxies `/api` to `VITE_API_TARGET`
(default `http://127.0.0.1:8000`).

## Related pages

- [First dashboard run](../getting-started/first-dashboard-run.md)
- [Advisory ML](advisory-ml.md)
- [Generate reports](generate-reports.md)
- [API reference](../reference/api.md)
- [Job lifecycle](../operations/job-lifecycle.md)
- [Dashboard navigation simplification](../../plans/proposals/dashboard-navigation-simplification.md)

## Implementation anchors

- `frontend/src/App.tsx`
- `frontend/src/pages/catalog_page.tsx`
- `frontend/src/pages/case_page.tsx`
- `frontend/src/pages/upload_page.tsx`
- `frontend/src/components/case_view.tsx`
- `src/securemail/api/main.py`
- `src/securemail/application/analysis_workflow.py`

## Test evidence

- `tests/e2e/dashboard.spec.ts`
- `frontend/src/App.test.tsx`
- `tests/test_report_api.py`
- `tests/test_analysis_api.py`
- `tests/test_capture_acceptance.py`
