---
status: current
audience: operator
authoritative_for: air-gap analysis constraints and missing signed bundle
last_verified: 2026-09-06
---

# Air-gapped operation

SecureMail is designed to **analyze** without network. Analyzer containers
always pass `--network=none`. Workers do not fetch AIA, OCSP, CRL, CT, DNS,
IANA, models, or telemetry at analysis time. Policy YAML, the IANA snapshot,
the trust-store PEM, bundled fonts, Zeek scripts, and fixture captures (Git
LFS) are in-repo.

Installing and building images currently needs a one-time fetch unless you
already have the artifacts. Companion narrative:
[offline installation](../getting-started/offline-installation.md).

## What is not packaged

There is **no** signed offline bundle, checksum manifest, SBOM, or
first-party `docker save` workflow in this repository.

TShark is the local tag `securemail/tshark:step0`. The lock records the
Dockerfile SHA-256, not a content-pinned image digest. A `docker save` of a
digest-pinned SecureMail TShark image does not exist. Rebuilding later can
produce a different TShark (**known limitation**).

The host Python process (CLI, Uvicorn, worker, WeasyPrint, sklearn) is
**not** OS-network-sandboxed. Offline operation of the API/CLI depends on an
air-gapped host or operational controls. Only analyzer containers pass
`--network=none`.

## Practical transfer (manual)

On a networked builder:

1. Clone with Git LFS and `git lfs pull`.
2. `uv sync --extra dev --extra reports --extra ml --extra api` and copy the
   uv cache / venv if you must.
3. `npm --prefix frontend ci` and copy `frontend/node_modules` or a pack.
4. `docker pull zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3`
5. `make zeek-image` and `make tshark-image`
6. `docker save` those images and the Zeek base; transfer with the repo tree.

On the air-gapped host: `docker load`, restore the tree, run `make doctor`
and a fixture `analyze`.

Do not expect a product-signed installer. Pin verification is
`tools/analyzer-bundle.lock` plus `make doctor`.

## Runtime expectations once air-gapped

- `securemail analyze` / the worker must not need outbound network if images
  and the venv already exist.
- `/health` still does not verify isolation.
- Advisory Isolation Forest uses in-process sklearn; no model download.
- Trust store is the committed PEM snapshot, not the host CA bundle.

## Related pages

- [Offline installation](../getting-started/offline-installation.md)
- [Security hardening](security-hardening.md)
- [Toolchain](../reference/toolchain.md)
- [As-built analyzers](../architecture/analyzer-boundary.md)

## Implementation anchors

- `src/securemail/adapters/analyzers/sandbox.py`
- `tools/analyzer-bundle.lock`
- `src/securemail/adapters/pki/` (trust-store snapshot)

## Test evidence

- `tests/unit/test_bundle_lock.py`
- `tests/unit/test_analyzer_argv.py`
- `tests/test_certificate_chain_fixtures.py` (no-inet guard)
