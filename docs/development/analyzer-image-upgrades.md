---
status: current
audience: contributor
authoritative_for: analyzer lockfile and image rebuild procedure
last_verified: 2026-09-06
---

# Analyzer image upgrades

Do not hand-edit [`tools/analyzer-bundle.lock`](../../tools/analyzer-bundle.lock).
Regenerate it:

```bash
make analyzer-lock
```

That runs `uv run python tools/refresh_analyzer_lock.py`.

| Lock key | Meaning |
|---|---|
| `zeek_image_digest` | Pinned upstream `zeek/zeek:8.0.10` digest |
| `zeek_bundle_sha256` | Hash of the `zeek/` tree |
| `tshark_image_digest` | SHA-256 of `docker/tshark/Dockerfile` bytes — **not** the built image digest |

`AnalysisRun.analyzer_bundle_digest` is SHA-256 of the **lockfile file bytes**.
Runners refuse to start if the on-disk `zeek/` hash, Zeek base digest, TShark
Dockerfile hash, or Zeek image labels disagree with the lock.

## Rebuild local tags

```bash
docker pull zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3
make tshark-image
make zeek-image
```

Tags stay `securemail/zeek:step0` and `securemail/tshark:step0`. Zeek is
labeled with `securemail.zeek_bundle_sha256` and `securemail.zeek_base_digest`
at build time.

Changing Zeek 8.0.10 LTS to 8.2 or 9.x is a deliberate lock + **every fixture**
refresh. See [golden updates](golden-updates.md).

## Known limitation

TShark runtime checks that `securemail/tshark:step0` exists and that the
Dockerfile hash matches the lock. It does **not** verify local image bytes,
Debian package version, or labels. `apt-get install tshark` in the Dockerfile
is unversioned, so rebuilding later can produce a different TShark.

CI job `digest-resolve` runs `docker manifest inspect` on the pinned Zeek
digest and the Debian Trixie slim digest parsed from
`docker/tshark/Dockerfile`.

## Related pages

- [Toolchain](../reference/toolchain.md)
- [Analyzer isolation](../security/analyzer-isolation.md)
- [Make targets](make-targets.md)

## Implementation anchors

- `tools/refresh_analyzer_lock.py`
- `src/securemail/adapters/analyzers/sandbox.py`
- `src/securemail/adapters/analyzers/bundle_lock.py`

## Test evidence

- `tests/unit/test_bundle_lock.py`
- `tests/unit/test_analyzer_argv.py`
- CI `digest-resolve`
