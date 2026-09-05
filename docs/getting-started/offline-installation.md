---
status: current
audience: operator
authoritative_for: what can and cannot be installed offline today
last_verified: 2026-09-06
---

# Offline installation

SecureMail is designed to **analyze** without network. Installing and building
analyzer images currently needs a one-time fetch unless you already have the
pinned artifacts.

## What is already in-repo

- Policy YAML packs
- IANA TLS Parameters snapshot
- Offline trust-store PEM
- Bundled report fonts
- Fixture captures (Git LFS)
- Zeek scripts (hashed into the lockfile)

Analysis workers do not fetch AIA, OCSP, CRL, CT, DNS, IANA, or models.

## What is not packaged

There is **no** signed offline bundle, checksum manifest, SBOM, or
`docker save` workflow in this repository.

TShark is the local tag `securemail/tshark:step0`. The lock records the
Dockerfile SHA-256, not a content-pinned image digest. A `docker save` of a
digest-pinned SecureMail TShark image does not exist.

The host Python process is **not** OS-network-sandboxed. Offline operation of
the API/CLI depends on an air-gapped host or operational controls. Only
analyzer containers pass `--network=none`.

## Practical air-gap transfer (manual)

On a networked builder:

1. Clone with Git LFS and `git lfs pull`.
2. `uv sync --extra dev --extra reports --extra ml --extra api` and copy the
   uv cache / venv if you must.
3. `npm --prefix frontend ci` and copy `frontend/node_modules` or a pack.
4. `docker pull zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3`
5. `make zeek-image` and `make tshark-image`
6. `docker save` those images and the Zeek base; transfer with the repo tree.

On the air-gapped host, `docker load`, restore the tree, and run
`make doctor` / a fixture `analyze`. See
[air-gapped operation](../operations/air-gapped-operation.md).

## Related pages

- [Analyzer isolation](../security/analyzer-isolation.md)
- [Current security limitations](../security/current-security-limitations.md)
- [Toolchain](../reference/toolchain.md)
