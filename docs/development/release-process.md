---
status: current
audience: contributor
authoritative_for: current release process and what is not published
last_verified: 2026-09-06
---

# Release process

Package version is **`0.0.0`** in [`pyproject.toml`](../../pyproject.toml)
and `frontend/package.json`. This repository has:

- **no** changelog pipeline
- **no** package publish (`pypi`, `npm publish`)
- **no** container registry publish for `securemail/zeek:step0` or
  `securemail/tshark:step0`

Those absences are intentional for this build. Do not add a release
automation in a documentation-only change.

## Pre-merge checklist

Run locally (or rely on CI equivalents):

```bash
make lint
make test
```

[Documentation style](documentation-style.md) also names `make docs-check`.
That target is not in the current `Makefile`; when it exists, add it to this
list. Do not regenerate PCAP fixtures as part of a documentation edit.

Also run when the change touches the named surface:

- schema / template / fonts → report tests + `npm --prefix frontend run generate:types`
- Zeek / lockfile / trust store → [golden updates](golden-updates.md)
- dashboard UI → `make frontend-build` and `make e2e`
- analyzer Dockerfiles → `make analyzer-lock` plus `digest-resolve` in CI

Do not skip git hooks (`--no-verify`) unless the operator explicitly requests
it outside this document.

## Related pages

- [CI](ci.md)
- [Make targets](make-targets.md)
- [Current capabilities](../status/current-capabilities.md)

## Implementation anchors

- `pyproject.toml` `version = "0.0.0"`
- `frontend/package.json` `"version": "0.0.0"`
- `.github/workflows/ci.yml`
