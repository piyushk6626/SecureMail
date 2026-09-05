---
status: current
audience: contributor
authoritative_for: Makefile targets and exact recipes
last_verified: 2026-09-06
---

# Make targets

Source: [`Makefile`](../../Makefile). On Darwin the Makefile exports
`DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib` so the uv interpreter can load
Homebrew Pango.

| Target | Recipe |
|---|---|
| `make doctor` | `uv run python tools/doctor.py` |
| `make sync` | `uv sync --all-extras` **and** `npm --prefix frontend ci` |
| `make lint` | `ruff check` + `ruff format --check` on `src tests tools`; `mypy`; `lint-imports`; `npm --prefix frontend run lint`; `npm --prefix frontend run typecheck` |
| `make test` | `pytest tests/unit tests/support tests -q --ignore=tests/fixtures/generators` then `npm --prefix frontend run test` (Vitest) |
| `make frontend-build` | `npm --prefix frontend run build` |
| `make e2e` | `npm --prefix frontend run test:e2e` (Playwright; stub analysis) |
| `make docs-check` | `uv run python tools/check_docs.py` (frontmatter, relative links, stale paths, hub coverage) |
| `make analyzer-lock` | `uv run python tools/refresh_analyzer_lock.py` |
| `make zeek-image` | `docker build -f docker/zeek/Dockerfile` tagged `securemail/zeek:step0` with bundle SHA and base digest build-args |
| `make tshark-image` | `docker build -f docker/tshark/Dockerfile` tagged `securemail/tshark:step0` |

`make docs-check` runs `tools/check_docs.py` for frontmatter, relative
Markdown links, stale plan paths, and `docs/README.md` hub coverage.

`make sync` does **not** pass `uv sync --locked`. Neither does CI.

`make test` does **not** execute generator scripts as pytest.

Analyzer image tags stay `*:step0` (historical name). Do not retag without
updating runners.

## Doctor checks

[`tools/doctor.py`](../../tools/doctor.py) prints every check, then exits 1 if
any failed:

| Line | Requirement |
|---|---|
| uv ≥ 0.11 | `uv` on PATH |
| python 3.13.x via uv | `uv python find 3.13` |
| git-lfs installed | `git lfs version` |
| docker daemon reachable | `docker info` |
| zeek/zeek@sha256:73e80e9c… matches lock | lock digest + image or manifest |
| pango visible via pkg-config | ≥ 1.58 |
| openssl reports OpenSSL (not LibreSSL) | macOS: `/opt/homebrew/bin/openssl` only |
| node | 22.12+ and `frontend/.nvmrc` contains `22` |

`SECUREMAIL_CI=1` still runs the checks; it prints that Docker Desktop-specific
notes are skipped.

## Related pages

- [Toolchain](../reference/toolchain.md)
- [CI](ci.md)
- [Workstation setup](workstation-setup.md)

## Implementation anchors

- `Makefile`
- `tools/doctor.py`

## Test evidence

- CI `lint-test` job invokes `make doctor`, `make lint`, `make test`, `make frontend-build`
