---
status: current
audience: contributor
authoritative_for: GitHub Actions CI jobs as implemented
last_verified: 2026-09-06
---

# CI

Workflow: [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml).
Triggers: `push` and `pull_request`. Three jobs.

There is **no** `uv sync --locked`. There is **no** coverage threshold.

## `lint-test`

`ubuntu-latest`. Checkout with LFS. uv Python 3.13. Node from
`frontend/.nvmrc` with npm cache on `frontend/package-lock.json`.

1. Native packages: git-lfs, pkg-config, Pango/Cairo/gdk-pixbuf/harfbuzz
2. `uv sync --extra dev --extra reports --extra ml --extra api`
3. `npm --prefix frontend ci`
4. `SECUREMAIL_CI=1 make doctor`
5. `make lint`
6. `make docs-check`
7. Pull pinned Zeek image; `make zeek-image`; `make tshark-image`
8. `make test`
9. `make frontend-build`

## `dashboard-e2e`

Needs `lint-test`. Syncs `uv sync --extra api --extra dev` (not reports/ml).
Installs Playwright Chromium with deps. Runs `make e2e`.

Playwright starts Uvicorn with `SECUREMAIL_ANALYSIS_STUB=1` so this job does
not rebuild analyzer images.

## `digest-resolve`

Independent. Parses `tools/analyzer-bundle.lock` and
`docker/tshark/Dockerfile` for the Debian Trixie slim digest, then
`docker manifest inspect` on both pins.

## Related pages

- [Make targets](make-targets.md)
- [Toolchain](../reference/toolchain.md)
- [Testing](testing.md)

## Implementation anchors

- `.github/workflows/ci.yml`
- `frontend/playwright.config.ts`

## Test evidence

- The workflow file is the proof; there is no extra CI unit test
