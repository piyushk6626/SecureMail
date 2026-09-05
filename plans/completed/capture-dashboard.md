# Post-Step-11: Offline capture analysis dashboard

**Status:** Approved contract for the single-host capture-upload phase.
**Does not reopen** Steps 0–11. Those remain complete. This phase adds a
filesystem-backed upload → analyze → advisory → report workflow on top of the
existing CLI, canonical report schema, and read-only catalog.

Companion sources of truth:

| Question | Source |
|---|---|
| Analyzer sandbox, evidence states, policy, scoring | `plans/TECHNICAL_DESIGN.md`, `AGENTS.md` |
| Existing file layout and import rules | `plans/PROJECT_SCAFFOLD.md` |
| Prior step contracts | `plans/build_plan.md` |
| This phase | **this file** |

---

## 1. Deployment and threat model

- Single trusted workstation / appliance. No multi-user accounts, OIDC, or
  case ownership in this phase.
- Analysis remains offline: Zeek/TShark keep `--network=none`. The API does
  not fetch AIA, OCSP, CRL, CT, DNS, models, or telemetry.
- No Postgres, Redis, RabbitMQ, Celery, or docker-compose control plane.
- Docker analyzers **never** run inside a FastAPI request or Starlette
  `BackgroundTasks`. A dedicated local worker process (or the same
  `process_once` entry the process loops on) executes them.
- Browser and API share a same-origin boundary. Existing security headers stay.

## 2. Limits

| Limit | Default | Notes |
|---|---|---|
| Capture upload | 64 MiB | Configurable `SECUREMAIL_MAX_CAPTURE_BYTES` |
| Capture name | 255 chars | Basename only; never used as a Docker mount string |
| Concurrent jobs | 64 | Reject new uploads at the cap |
| Data-root jobs+history | 2 GiB | Reject when the next write would exceed |
| Canonical JSON | 8 MiB | Existing `MAX_REPORT_BYTES` |
| HTML artifact | 16 MiB | Stored beside the job |
| PDF artifact | 32 MiB | Stored beside the job |
| ML history windows | 512 | Oldest dropped first |
| Catalog reports | 256 | Existing catalog cap |
| Case / run IDs | `[A-Za-z0-9][A-Za-z0-9._-]{0,159}` | Same alphabet as Step 11 |

Magic bytes must match the extension:

- `.pcapng` → `\x0a\x0d\x0d\x0a`
- `.pcap` → libpcap little/big endian, including swapped nanosecond variants

Mismatch, empty file, symlink, or non-regular file → 400. Oversize → 413.

## 3. Filesystem layout

`SECUREMAIL_DATA_ROOT` holds jobs, quarantine, and ML history.
`SECUREMAIL_REPORT_ROOT` remains the canonical-report catalog (defaults to the
data root when unset).

```text
{data_root}/
  quarantine/{upload_id}.part
  jobs/{run_id}/
    status.json
    capture.pcap|capture.pcapng
    cancel.flag          # present when cancel is requested
    artifacts/
      report.json
      report.html
      report.pdf
  ml_history/windows.jsonl
{report_root}/
  catalog.json
  {case_id}.report.json
```

Paths are generated from trusted IDs. Original filenames are metadata only.
Symlinks, `..`, and absolute catalog paths stay forbidden.

## 4. Job states and stages

Status: `queued` → `running` → `completed` | `failed` | `cancelled`.

Stages, in order:

1. `intake`
2. `deterministic_analysis`
3. `policy_scoring` (included in `run_analysis`; recorded when scoring starts)
4. `ml_advisory`
5. `report_rendering`
6. `publication`

Cancel is cooperative: the worker checks `cancel.flag` between stages. A
duplicate upload of the same `(capture_sha256, policy_profile,
expected_hostname)` returns the existing queued, running, or completed run
instead of creating a second job.

## 5. Pipeline

1. Stream the upload to quarantine while hashing. Validate extension + magic.
   Move to `jobs/{run_id}/capture.*` and enqueue.
2. Worker calls existing `run_analysis` (Zeek + bounded TShark, policy, dedup,
   score).
3. `assemble_report` builds one `securemail.report/v1` object from the
   `EvidenceDocument` (manifest, limitations, provenance). It does not invent
   certificates, plaintext, or passes from `not_observable` / `incomplete`.
4. Extract endpoint-windows, merge with persisted local history, run baseline
   and Isolation Forest. Persist the new windows. ML never mutates findings.
5. History rules:
   - `< 14` windows: advisory code `ADVISORY_INSUFFICIENT_HISTORY` only
     (never `ADVISORY_NONE`).
   - `14–39` windows: baseline may score; Isolation Forest still emits
     `ADVISORY_INSUFFICIENT_HISTORY`.
   - `≥ 40` windows: both detectors run; `ADVISORY_NONE` is allowed when
     nothing is above threshold.
6. Render JSON, HTML, and PDF from **one** in-memory canonical object. Publish
   JSON into the catalog atomically and store HTML/PDF as job artifacts.

## 6. HTTP API

Existing Step 11 routes stay. Add:

| Method | Path | Result |
|---|---|---|
| `POST` | `/api/v1/analyses` | `202` `{run_id,case_id,status,capture_sha256}` |
| `GET` | `/api/v1/analyses/{run_id}` | Job status and artifact flags |
| `POST` | `/api/v1/analyses/{run_id}/cancel` | Cooperative cancel |
| `GET` | `/api/v1/analyses/{run_id}/report` | Canonical JSON |
| `GET` | `/api/v1/analyses/{run_id}/report.html` | `text/html` attachment |
| `GET` | `/api/v1/analyses/{run_id}/report.pdf` | `application/pdf` attachment |
| `GET` | `/api/v1/cases/{case_id}/report.html` | HTML from catalog JSON |
| `GET` | `/api/v1/cases/{case_id}/report.pdf` | PDF from catalog JSON |

`POST /api/v1/analyses` is `multipart/form-data` with `file` (required) and
optional `policy_profile`, `expected_hostname`, `case_id`.

Errors: 400 validation, 404 unknown run/case, 409 cancel of a terminal job,
413 oversize, 503 catalog/worker/storage failure. Bodies stay `{ "detail": ... }`.
No filesystem paths in responses.

## 7. UI contract

- Primary intake is PCAP/PCAPNG drag-and-drop, not canonical JSON.
- Poll job status through the listed stages; allow cancel while queued/running.
- After `completed`, show the case view and enable HTML/PDF download.
- Four labeled regions remain separate: Observed Facts, Deterministic
  Conclusions, Advisory / ML, Analyst Notes.
- Widgets may use only fields on `CanonicalReport` (risk, findings, coverage,
  protocol inventory, TLS versions, STARTTLS state, certificate facts,
  limitations). No fabricated trend deltas.
- Dark-first navy/charcoal console, cyan accent, semantic severity colors,
  light theme preserved, WCAG AA, reduced motion, hostile-text isolation,
  no-case-selected isolation.

## 8. Environment

| Variable | Role |
|---|---|
| `SECUREMAIL_REPORT_ROOT` | Canonical catalog (Step 11) |
| `SECUREMAIL_DATA_ROOT` | Jobs, quarantine, ML history |
| `SECUREMAIL_START_WORKER` | `1` starts the out-of-process worker from the API entry |
| `SECUREMAIL_ANALYSIS_STUB` | `1` skips Docker (UI/e2e only; not the acceptance proof) |
| `SECUREMAIL_MAX_CAPTURE_BYTES` | Override upload cap |

## 9. Acceptance proofs

1. Unit/API: magic/extension mismatch, oversize, traversal/symlink, disconnect
   cleanup, duplicate idempotency, cancel, ML-history thresholds, atomic
   catalog publish, download headers.
2. One real fixture: upload `tests/fixtures/empty/capture.pcapng` over HTTP,
   sandboxed `run_analysis`, assemble, advisory (insufficient history on a
   fresh data root), HTML/PDF download, findings unchanged by ML, no network.
3. Playwright: PCAP upload/progress, catalog selection, four regions, hostile
   text, case isolation, downloads, reduced motion, light/dark.

Production proof:

```bash
SECUREMAIL_DATA_ROOT=out/data SECUREMAIL_REPORT_ROOT=out/data \
  SECUREMAIL_START_WORKER=1 \
  uv run uvicorn securemail.api.main:app
```
