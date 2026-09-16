---
status: current
audience: contributor
authoritative_for: dashboard frontend toolchain and type generation
last_verified: 2026-09-15
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

The bundled interface fonts are `@fontsource-variable/ibm-plex-sans` and
`@fontsource/ibm-plex-mono`; do not replace them with a remote font request.
`src/styles.css` owns the Evidence Ledger tokens and responsive/forced-colors
rules. Canonical evidence-state presentation is centralized in
`src/components/ui.tsx`, including the distinct `not_observable` tone.

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
| `src/App.tsx` | Dark-only shell, logo, client routes |
| `src/pages/` | Catalog, case detail, upload |
| `src/core/api.ts` | Fetch wrappers |
| `src/core/selectors.ts` | View models over generated types |
| `src/core/evidence_resolver.ts` | Resolve `EvidenceReference` against the report |
| `src/core/forensic_text.ts` | Control/bidi visibility (presentation only) |
| `src/components/case_view.tsx` | Case detail |
| `src/components/findings_table.tsx` | Prioritized findings |
| `src/components/finding_details.tsx` | Evidence links |

The resolver accepts both relative and matching target-qualified paths (for
example `version.selected` and `handshake.version.selected`) and the four
documented presentation-only `derived.*` paths. It never evaluates policy in
the browser. Unknown paths still display a raw path and explicit unavailable
state; do not add a fallback that guesses a value.

## Local API

For upload, progress, cancellation, or completed-report development, use the
standard worker-backed API:

```bash
make dashboard-api
```

In another terminal, start Vite:

```bash
make frontend-dev
```

`make dashboard-api` uses `out/local-dashboard` by default. Override it with
`make dashboard-api DASHBOARD_DATA_ROOT=out/another-root`. Before treating the
dashboard as ready for uploads, verify that `python -m securemail.worker` is a
child of Uvicorn.

Fixture-only catalog browse is a separate, non-upload workflow:

```bash
make dashboard-catalog
```

It runs on port 8001 with the worker disabled so it cannot silently replace
the upload-capable API on port 8000. Do not use it to test `/upload`.

Playwright e2e copies dashboard JSON into `out/e2e-data`, starts Uvicorn on
port 8011 with `SECUREMAIL_ANALYSIS_STUB=1`, and Vite on `127.0.0.1:5174` with
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
