# Contributing

This repository is a deterministic-first forensics tool. Read
[`AGENTS.md`](AGENTS.md) before changing code, tests, fixtures, Dockerfiles, or
documentation.

## Workflow

1. Follow [workstation setup](docs/development/workstation-setup.md).
2. Put code in the file named by [repository map](docs/development/repository-map.md).
   Do not invent parallel modules.
3. For evidence behavior, author or extend `tests/fixtures/<case_id>/` **before**
   the Zeek script or Python that should satisfy it. Captures are git-lfs and
   immutable after creation. See [fixture contract](docs/development/fixture-contract.md).
4. Keep clean-architecture import direction
   ([coding and import boundaries](docs/development/coding-and-import-boundaries.md)).
5. Missing evidence is not a pass. Do not treat `not_observable`, `incomplete`,
   or `indeterminate` as secure.

## Checks

```bash
make doctor
make lint
make test
make docs-check
```

Frontend: `npm --prefix frontend run lint`, `typecheck`, `test`. E2E needs
Playwright Chromium (`npx playwright install chromium`) then `make e2e`.

Analyzer image or `zeek/` changes require `make analyzer-lock`, image rebuilds,
and golden updates. See
[analyzer image upgrades](docs/development/analyzer-image-upgrades.md) and
[golden updates](docs/development/golden-updates.md).

## Documentation

Pages under `docs/` use YAML frontmatter and the
[documentation style](docs/development/documentation-style.md). One fact lives
on one page. Do not copy CLI/API/limit tables.

## What not to add

PostgreSQL, Celery/RabbitMQ, OIDC, Kubernetes, and similar control-plane pieces
are **deferred** unless an approved file appears under `plans/proposals/`.
[`docs/future/`](docs/future/README.md) is not that approval.

## Related pages

- [Testing](docs/development/testing.md)
- [CI](docs/development/ci.md)
- [Release process](docs/development/release-process.md)
- [Security policy](SECURITY.md)
