---
status: current
audience: operator
authoritative_for: Linux developer and CI-equivalent setup
last_verified: 2026-09-06
---

# Linux setup

Ubuntu is the CI-validated Linux environment
([`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)). Other
distributions are unvalidated.

## Native packages

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  git-lfs pkg-config libpango1.0-dev libcairo2 \
  libgdk-pixbuf-2.0-0 libharfbuzz0b
git lfs install
git lfs pull
```

Install Docker Engine, `uv`, Node 22 (see `frontend/.nvmrc`), and CPython 3.13
via uv. Do not use system Python 3.12/3.14.

```bash
uv python install 3.13
uv sync --extra dev --extra reports --extra ml --extra api
cd frontend && nvm install && nvm use && npm ci && cd ..
docker pull zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3
make tshark-image
make zeek-image
SECUREMAIL_CI=1 make doctor
make lint
make test
make frontend-build
```

E2E (matches CI):

```bash
cd frontend && npx playwright install --with-deps chromium && cd ..
make e2e
```

`DYLD_FALLBACK_LIBRARY_PATH` is macOS-only. Linux WeasyPrint uses distro
Pango via pkg-config.

## Related pages

- [Supported platforms](supported-platforms.md)
- [CI](../development/ci.md)
- [Toolchain](../reference/toolchain.md)
