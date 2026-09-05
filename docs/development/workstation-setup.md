---
status: current
audience: contributor
authoritative_for: extra contributor workstation steps beyond getting-started
last_verified: 2026-09-06
---

# Workstation setup

Install the operator toolchain first:

1. [Supported platforms](../getting-started/supported-platforms.md)
2. [macOS Apple Silicon](../getting-started/macos-apple-silicon.md) or
   [Linux](../getting-started/linux.md)
3. [Offline installation](../getting-started/offline-installation.md) when needed

Do not copy brew/apt pin tables onto this page.

## Contributor extras

After `make doctor` is green:

```bash
make sync
make lint
make test
```

`make sync` runs `uv sync --all-extras` and `npm --prefix frontend ci`. CI
uses `uv sync --extra dev --extra reports --extra ml --extra api` and does
**not** pass `--locked`.

Optional:

- `pre-commit` is in the `dev` extra; hooks are not required to land a change
- Playwright Chromium: `cd frontend && npx playwright install --with-deps chromium`
- Lab fixture generation needs Docker plus a tcpdump sidecar — see
  [fixture generation](fixture-generation.md)

PDF rendering needs Homebrew Pango (macOS) or the CI native packages (Linux).
Do not `brew install weasyprint`.

OpenSSL cross-check tests on macOS use `/opt/homebrew/bin/openssl` only.

## Verify

```bash
make doctor
make lint
make test
make frontend-build
```

End-to-end dashboard tests (`make e2e`) start Uvicorn with
`SECUREMAIL_ANALYSIS_STUB=1` and do not require analyzer images.

## Related pages

- [Make targets](make-targets.md)
- [Toolchain](../reference/toolchain.md)
- [CI](ci.md)

## Implementation anchors

- `tools/doctor.py`
- `Makefile`
- `frontend/.nvmrc`

## Test evidence

- CI job `lint-test` runs the same doctor/lint/test sequence on `ubuntu-latest`
