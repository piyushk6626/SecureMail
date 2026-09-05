---
status: current
audience: operator
authoritative_for: which environments and extras are validated
last_verified: 2026-09-06
---

# Compatibility matrix

Platform rules are owned by
[supported platforms](../getting-started/supported-platforms.md). Pins are
owned by [toolchain](../reference/toolchain.md). This page is the matrix.

| Environment | Status |
|---|---|
| Apple Silicon macOS, Homebrew `/opt/homebrew` | **Implemented** (primary workstation) |
| Ubuntu Linux (`ubuntu-latest` GitHub Actions) | **Implemented** (CI-validated) |
| Analyzer images `linux/amd64` and `linux/arm64` | **Implemented** (Dockerfiles) |
| Intel macOS Homebrew `/usr/local` | **Unsupported** |
| Windows | **Unsupported** |
| Multi-node / Kubernetes | **Deferred** |

No GPU is required.

## Python extras

| Extra | Needed for | Status |
|---|---|---|
| (default) | `analyze`, JSON/HTML | **Implemented** |
| `reports` | PDF (WeasyPrint 69.0) | **Implemented** |
| `ml` | `evaluate-ml`, `--advisory` | **Implemented** |
| `api` | FastAPI dashboard | **Implemented** (also unused SQLAlchemy extras) |
| `dev` | pytest, ruff, mypy, Playwright, … | **Implemented** |

## Analyzers

| Image | Pin | Status |
|---|---|---|
| Zeek 8.0.10 LTS | digest in lockfile | **Implemented** |
| TShark on Debian Trixie slim | Dockerfile hash in lockfile | **Implemented** with content-pin **Known limitation** |

## Frontend

Node 22 (`frontend/.nvmrc`). Vite 8 needs 22.12+.

## Related pages

- [Supported platforms](../getting-started/supported-platforms.md)
- [Toolchain](../reference/toolchain.md)
- [CI](../development/ci.md)
