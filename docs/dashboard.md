# Interactive dashboard

Step 11 adds a read-only FastAPI control plane and a React analyst dashboard
over the existing `securemail.report/v1` contract. The API and UI do not run
packet analysis, change findings, or persist browser uploads.

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

Start the API with an optional directory of canonical reports:

```bash
SECUREMAIL_REPORT_ROOT=tests/fixtures/dashboard \
  uv run uvicorn securemail.api.main:app --reload
```

In another terminal, start Vite:

```bash
npm --prefix frontend run dev
```

Vite proxies `/api` to `http://127.0.0.1:8000`. After
`npm --prefix frontend run build`, FastAPI serves the built single-page
application from `frontend/dist`.

## Inputs and case isolation

The dashboard accepts only canonical report JSON, not PCAP/PCAPNG captures.
There are two sources:

- the server catalog configured by `SECUREMAIL_REPORT_ROOT`;
- a JSON file previewed through the API and retained only in browser memory.

Every report fetch names a case explicitly. There is no implicit current or
latest report, report queries are disabled until a selection is made, and
clearing a selection removes the prior report from the rendered view. Full
OIDC/RBAC is Phase 2; deploy this MVP behind the organization's trusted
same-origin access boundary.

## API

- `GET /api/v1/health`
- `GET /api/v1/cases`
- `GET /api/v1/cases/{case_id}/report`
- `POST /api/v1/reports/preview`

Full report responses are RFC 8785 bytes produced by the same application
operation used by `securemail report`. Preview bodies and catalog files are
bounded to 8 MiB and validated as `CanonicalReport`.

## Analyst views

The case view keeps four labeled regions separate:

1. Observed Facts
2. Deterministic Conclusions
3. Advisory / ML
4. Analyst Notes

Findings retain their evidence state and link to the referenced record, field,
and frame number when available. Unknown, incomplete, indeterminate, and
not-observable evidence are never presented as passes. Hostile report strings
are rendered as text, with control and bidirectional characters made visible.

## Verification

```bash
make lint
make test
make frontend-build
make e2e
```

The API contract test compares response bytes with CLI-generated canonical
JSON. Playwright covers upload and catalog selection, filtering, evidence
drill-down, the four-region boundary, hostile text, responsive presentation,
and no-case-selected isolation.
