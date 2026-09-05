# Interactive dashboard

The dashboard is a FastAPI + React analyst console over `securemail.report/v1`.
It can preview cataloged reports and run **offline PCAP/PCAPNG analysis** on a
single trusted workstation. Packet decoding still happens in sandboxed Zeek and
TShark, never in the browser.

## Development

Use CPython 3.13 and Node 22:

```bash
uv sync --extra api --extra dev --extra reports --extra ml
cd frontend
nvm install
nvm use
npm ci
cd ..
```

Start the API with a writable data root (jobs, ML history, published reports)
and a worker process:

```bash
SECUREMAIL_DATA_ROOT=out/data SECUREMAIL_REPORT_ROOT=out/data \
  SECUREMAIL_START_WORKER=1 \
  uv run uvicorn securemail.api.main:app --reload
```

To browse committed catalog fixtures without analysis:

```bash
SECUREMAIL_REPORT_ROOT=tests/fixtures/dashboard \
  uv run uvicorn securemail.api.main:app --reload
```

In another terminal:

```bash
npm --prefix frontend run dev
```

Vite proxies `/api` to `http://127.0.0.1:8000`. After
`npm --prefix frontend run build`, FastAPI serves `frontend/dist`.

## Capture upload

Primary intake is `.pcap` / `.pcapng` (magic bytes must match the extension).
The API streams the file to quarantine, hashes it, and enqueues a job. A
dedicated worker process runs `run_analysis`, assembles a canonical report,
runs advisory ML against bounded local history, and publishes JSON/HTML/PDF.

Until 14 (baseline) / 40 (Isolation Forest) endpoint-windows exist locally,
the Advisory / ML region shows `ADVISORY_INSUFFICIENT_HISTORY` rather than
implying that no anomaly was found. ML never edits deterministic findings.

## Inputs and case isolation

Sources:

- the server catalog (`SECUREMAIL_REPORT_ROOT`);
- captures analyzed on this host (`SECUREMAIL_DATA_ROOT`).

Every report fetch names a case or analysis run explicitly. There is no
implicit current/latest report. Clearing a selection removes prior evidence
from the view.

## API

- `GET /api/v1/health`
- `GET /api/v1/cases`
- `GET /api/v1/cases/{case_id}/report`
- `GET /api/v1/cases/{case_id}/report.html`
- `GET /api/v1/cases/{case_id}/report.pdf`
- `POST /api/v1/reports/preview`
- `POST /api/v1/analyses` (multipart PCAP/PCAPNG)
- `GET /api/v1/analyses/{run_id}`
- `POST /api/v1/analyses/{run_id}/cancel`
- `GET /api/v1/analyses/{run_id}/report`
- `GET /api/v1/analyses/{run_id}/report.html`
- `GET /api/v1/analyses/{run_id}/report.pdf`

Canonical JSON is RFC 8785. HTML/PDF are rendered from the same in-memory
object. Uploads default to 64 MiB. See
[`plans/post_step_11_capture_dashboard.md`](../plans/post_step_11_capture_dashboard.md).

## Analyst views

The case view keeps four labeled regions separate:

1. Observed Facts
2. Deterministic Conclusions
3. Advisory / ML
4. Analyst Notes

Findings retain their evidence state. Unknown, incomplete, indeterminate, and
not-observable evidence are never presented as passes. Hostile strings render
as text, with control and bidirectional characters made visible. HTML and PDF
downloads are offered after a run completes, and for catalog cases.

## Verification

```bash
make lint
make test
make frontend-build
make e2e
```
