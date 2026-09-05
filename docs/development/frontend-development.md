---
status: current
audience: contributor
authoritative_for: dashboard frontend toolchain and type generation
last_verified: 2026-09-06
---

# Frontend development

Node **22** via [`frontend/.nvmrc`](../../frontend/.nvmrc) (`22`). Doctor wants
22.12+ because Vite 8 requires it. Do not use the machine’s global Node 25.

```bash
cd frontend
nvm install
nvm use
npm ci
```

`make sync` already runs `npm --prefix frontend ci`.

## Scripts

| Script | Purpose |
|---|---|
| `npm run dev` | Vite on `127.0.0.1:5173`; proxies `/api` to `VITE_API_TARGET` (default `http://127.0.0.1:8000`) |
| `npm run build` | `tsc -b && vite build` → `frontend/dist` |
| `npm run lint` | ESLint `--max-warnings=0` |
| `npm run typecheck` | `tsc -b` |
| `npm run test` | Vitest once |
| `npm run test:e2e` | Playwright `tests/e2e/dashboard.spec.ts` |
| `npm run generate:types` | `json-schema-to-typescript` from `canonical_report.schema.json` |

After any `CanonicalReport` / evidence schema change:

```bash
npm --prefix frontend run generate:types
```

Do not hand-edit `frontend/src/types/canonical_report.generated.ts`.

## Layout

| Path | Role |
|---|---|
| `src/App.tsx` | Case list, four labeled regions |
| `src/core/api.ts` | Fetch wrappers |
| `src/core/selectors.ts` | View models over generated types |
| `src/core/evidence_resolver.ts` | Resolve `EvidenceReference` against the report |
| `src/core/forensic_text.ts` | Control/bidi visibility (presentation only) |
| `src/components/case_view.tsx` | Case detail |
| `src/components/findings_table.tsx` | Prioritized findings |
| `src/components/finding_details.tsx` | Evidence links |

**Known limitation:** the resolver walks `field_path` relative to the already
selected record. Engine references use qualified paths such as
`handshake.version.selected`. Vitest fixtures use `version.selected`. Live
findings can show as `dangling_field`. See
[known limitations](../status/known-limitations.md).

## Local API

Catalog browse (disable the worker explicitly):

```bash
SECUREMAIL_REPORT_ROOT=tests/fixtures/dashboard \
SECUREMAIL_START_WORKER=0 \
  uv run uvicorn securemail.api.main:app --reload
```

Analysis on this host:

```bash
SECUREMAIL_DATA_ROOT=out/data \
SECUREMAIL_REPORT_ROOT=out/data \
SECUREMAIL_START_WORKER=1 \
  uv run uvicorn securemail.api.main:app --reload
```

If a root is set and `SECUREMAIL_START_WORKER` is omitted, the worker
**starts**.

Playwright e2e copies dashboard JSON into `out/e2e-data`, starts Uvicorn on
port 8011 with `SECUREMAIL_ANALYSIS_STUB=1`, and Vite with
`VITE_API_TARGET=http://127.0.0.1:8011`.

On Apple Silicon the e2e script may set `PLAYWRIGHT_HOST_PLATFORM_OVERRIDE` to
`mac26-arm64`.

## Related pages

- [First dashboard run](../getting-started/first-dashboard-run.md)
- [API](../reference/api.md)
- [Environment variables](../reference/environment-variables.md)
- [Report schema](../reference/report-schema.md)

## Implementation anchors

- `frontend/package.json`
- `frontend/vite.config.ts`
- `frontend/playwright.config.ts`

## Test evidence

- Vitest files under `frontend/src/`
- `tests/e2e/dashboard.spec.ts`
