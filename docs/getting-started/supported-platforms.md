---
status: current
audience: operator
authoritative_for: supported and unvalidated platforms
last_verified: 2026-09-06
---

# Supported platforms

SecureMail is a **single-host** tool. Analyzer containers are Linux. The
orchestrator is host Python.

| Environment | Status |
|---|---|
| Apple Silicon macOS with Homebrew at `/opt/homebrew` | Primary workstation; documented and used in development |
| Ubuntu Linux (`ubuntu-latest` GitHub Actions) | CI-validated |
| Analyzer images `linux/amd64` and `linux/arm64` | Dockerfiles support both |
| Intel macOS Homebrew at `/usr/local` | **Unsupported** — doctor and PDF library paths assume `/opt/homebrew` |
| Windows | **Unsupported** — not documented, not CI-tested |
| Multi-node / Kubernetes | **Deferred** — see [future](../future/README.md) |

No GPU is required.

## Hardcoded macOS assumptions

- OpenSSL: `/opt/homebrew/bin/openssl` only (never `/usr/bin/openssl`)
- Native libraries: `/opt/homebrew/lib` via `DYLD_FALLBACK_LIBRARY_PATH`
- Playwright: `mac26-arm64` workaround in frontend config when present
- Docker Desktop provides the Linux analyzer runtime

Intel Macs that install Homebrew under `/usr/local` will fail doctor and PDF
rendering unless those paths are changed in code. That change is not supported
in this documentation.

## Related pages

- [macOS Apple Silicon](macos-apple-silicon.md)
- [Linux](linux.md)
- [Compatibility matrix](../status/compatibility-matrix.md)
- [Toolchain](../reference/toolchain.md)
