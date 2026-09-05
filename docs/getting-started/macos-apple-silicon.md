---
status: current
audience: operator
authoritative_for: Apple Silicon macOS workstation installation
last_verified: 2026-09-06
---

# macOS Apple Silicon setup

Target: Apple Silicon macOS with Homebrew prefix `/opt/homebrew`. See
[supported platforms](supported-platforms.md) before starting.

## Prerequisites

```bash
brew install uv git-lfs pango openssl@3 nvm
git lfs install
git lfs pull
uv python install 3.13
```

Homebrew `nvm` does not enable `nvm` in a new shell by itself. Follow Homebrew’s
post-install `nvm` shell snippet, then:

```bash
cd frontend
nvm install
nvm use
npm ci
cd ..
```

Do **not** `brew install weasyprint`. PDF uses the uv extra `reports`
(WeasyPrint 69.0) plus Homebrew Pango.

Do **not** use `/usr/bin/openssl`. Doctor requires
`/opt/homebrew/bin/openssl` reporting OpenSSL, not LibreSSL.

## Python, frontend, analyzers

```bash
uv sync --extra dev --extra reports --extra ml --extra api
docker info
docker pull zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3
make tshark-image
make zeek-image
```

`make sync` is equivalent to `uv sync --all-extras` plus `npm --prefix frontend ci`.

On Darwin the Makefile exports
`DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib` so the uv interpreter can load
Pango.

## Verify

```bash
make doctor
make lint
make test
make frontend-build
```

Doctor checks: uv ≥ 0.11, Python 3.13.x via uv, git-lfs, Docker daemon, Zeek
digest, Pango ≥ 1.58, Homebrew OpenSSL, Node 22.12+ matching `frontend/.nvmrc`.

Playwright Chromium is **not** installed by `make test`. For E2E:

```bash
cd frontend
npx playwright install chromium
cd ..
make e2e
```

## Common failures

| Symptom | Cause |
|---|---|
| `nvm: command not found` | Homebrew nvm shell init missing |
| WeasyPrint cannot load pango | `DYLD_FALLBACK_LIBRARY_PATH` unset; do not brew-install WeasyPrint |
| LibreSSL from `/usr/bin/openssl` | Use `/opt/homebrew/bin/openssl` |
| Analyzer digest mismatch | Rebuild `make zeek-image` / `make tshark-image` after lock/script changes |
| Fixture tests fail without Docker | `make test` runs real CLI against analyzer images |

## Related pages

- [Linux](linux.md)
- [First CLI analysis](first-cli-analysis.md)
- [Doctor / Make targets](../development/make-targets.md)
- [Toolchain](../reference/toolchain.md)
