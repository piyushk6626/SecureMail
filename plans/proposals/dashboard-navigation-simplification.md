---
status: current
audience: architect
authoritative_for: dashboard route map, dark-only shell, and post-sidebar navigation
last_verified: 2026-09-09
---

# Dashboard navigation simplification

**Status:** Approved post-Step-11 UI contract. It does **not** reopen Steps
0–11 or the capture-upload pipeline. HTTP analysis routes, sandboxed Zeek and
TShark, four labeled case regions, hostile-text isolation, and no-case
isolation remain in force.

This file is the live UI contract for dashboard navigation. It supersedes these
items from
[`../completed/capture-dashboard.md`](../completed/capture-dashboard.md) §7 and
§9:

- Sidebar as the home for catalog selection and capture upload
- Header Portfolio / Case mode toggle
- Header “API online” health pill
- Light theme (“light theme preserved”; Playwright light/dark proof)

Live operator behavior after implementation lives in
[`../../docs/user-guide/dashboard-workflows.md`](../../docs/user-guide/dashboard-workflows.md).

## Route map

| Path | View |
|---|---|
| `/` | Redirect to `/cases` |
| `/cases` | Catalog of published case summaries (no full evidence) |
| `/cases/:case_id` | Case detail (four labeled regions) |
| `/upload` | PCAP/PCAPNG intake, stage stepper, cancel, terminal errors |

Unknown frontend paths redirect to `/cases`. FastAPI still serves `/api/v1/*`
from the existing routers. Production static serving returns `frontend/dist`
`index.html` for extensionless client routes so a reload of `/cases`,
`/cases/:case_id`, or `/upload` does not 404.

A completed upload navigates to `/cases/{case_id}` and may pass `?run={run_id}`
so HTML/PDF links keep using job artifact URLs. Catalog opens omit `run`.

## Shell

- No persistent sidebar and no mobile navigation drawer.
- Header: `frontend/logo.png` at the top left (links to `/cases`) and one
  accessible **Upload capture** action that goes to `/upload`.
- No API health pill, no Portfolio/Case segmented buttons, no theme toggle.

“Back to catalog” on a case detail drops the visible case (React Query
`case-report` / `analysis` / `analysis-report` caches are removed) so another
case cannot leak into the catalog view.

## Design

Dark-only navy/charcoal console, cyan accent, semantic severity colors, WCAG
AA, reduced motion, hostile-text isolation. Light-theme tokens and
`localStorage` theme switching are removed.

Unchanged from the capture-dashboard contract:

- Primary intake is PCAP/PCAPNG, not canonical JSON
- Poll listed job stages; cancel while queued/running
- Widgets may use only `CanonicalReport` fields
- Four regions stay separate: Observed Facts, Deterministic Conclusions,
  Advisory / ML, Analyst Notes

## Acceptance proofs

1. Vitest: reject non-pcap upload; completed upload polls then shows case
   detail and HTML/PDF links; failed upload does not leak a prior case;
   catalog → case-a → case-b → catalog isolation.
2. Playwright: catalog filter and open-case; four regions; hostile text;
   case isolation; PCAP upload/progress/downloads; reduced motion; logo
   present; health/portfolio/case/theme controls absent; dark `color-scheme`.
3. API: static mount still preserves `/api/v1/*`; `GET /cases`,
   `GET /cases/{id}`, and `GET /upload` return the built `index.html`.

## Related pages

- [Capture-upload dashboard (completed)](../completed/capture-dashboard.md)
- [Dashboard workflows](../../docs/user-guide/dashboard-workflows.md)
- [Frontend data flow](../../docs/architecture/frontend-data-flow.md)
- [Proposals index](README.md)

## Implementation anchors

- `frontend/src/App.tsx`
- `frontend/src/pages/`
- `src/securemail/api/main.py`
- `tests/e2e/dashboard.spec.ts`
