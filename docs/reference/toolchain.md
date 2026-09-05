---
status: current
audience: contributor
authoritative_for: pinned toolchain versions
last_verified: 2026-09-06
---

# Toolchain

Pins come from repository files, not from this page. Re-verify digests rather
than silently changing versions.

| Tool | Pin | Source |
|---|---|---|
| CPython | 3.13.x (`>=3.13,<3.14`) | `.python-version`, `pyproject.toml`, `uv.lock` |
| uv | ≥ 0.11 | `tools/doctor.py` |
| Node | 22 (`>=22 <23`; doctor wants 22.12+) | `frontend/.nvmrc`, `frontend/package.json` |
| Zeek | 8.0.10 LTS | `zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3` |
| Debian Trixie slim (TShark base) | `sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132` | `docker/tshark/Dockerfile` |
| WeasyPrint | 69.0 | `pyproject.toml` extra `reports` |
| rfc8785 | 0.1.4 | `pyproject.toml` |
| OpenSSL (test-only) | Homebrew `/opt/homebrew/bin/openssl` on macOS | doctor; never `/usr/bin/openssl` (LibreSSL) |
| Pango | ≥ 1.58 via pkg-config | doctor |
| Git LFS | required for `*.pcap`, `*.pcapng`, `*.der`, `*.p12`, `*.pfx` | doctor |

Local analyzer tags: `securemail/zeek:step0`, `securemail/tshark:step0`.

Lockfile [`tools/analyzer-bundle.lock`](../../tools/analyzer-bundle.lock):

| Key | Meaning |
|---|---|
| `zeek_image_digest` | Pinned upstream Zeek image digest |
| `zeek_bundle_sha256` | Hash of the `zeek/` tree |
| `tshark_image_digest` | SHA-256 of `docker/tshark/Dockerfile` bytes — **not** the built image digest |

**Known limitation:** TShark runtime checks that `securemail/tshark:step0`
exists and that the Dockerfile hash matches the lock. It does not verify local
image bytes, Debian package version, or labels. `apt-get install tshark` is
unversioned, so rebuilding later can produce a different TShark.

## Python extras

| Extra | Provides | Needed for |
|---|---|---|
| (default) | pydantic, typer, cryptography, pyyaml, jinja2, rfc8785 | `analyze`, JSON/HTML |
| `reports` | WeasyPrint 69.0 | PDF |
| `ml` | scikit-learn, numpy, scipy | `evaluate-ml`, `--advisory` |
| `api` | FastAPI, Uvicorn, python-multipart, **and unused** SQLAlchemy/asyncpg/Alembic | dashboard |
| `dev` | pytest, hypothesis, ruff, mypy, import-linter, playwright, scapy, jsonschema, pypdf, httpx, pre-commit | contributors |

```bash
uv sync --extra dev --extra reports --extra ml --extra api
# equivalent:
make sync   # also runs npm --prefix frontend ci
```

`make sync` and CI do **not** pass `uv sync --locked`.

## Related pages

- [Supported platforms](../getting-started/supported-platforms.md)
- [Analyzer image upgrades](../development/analyzer-image-upgrades.md)
- [Make targets](../development/make-targets.md)

## Implementation anchors

- `pyproject.toml`
- `tools/doctor.py`
- `tools/analyzer-bundle.lock`
- `src/securemail/adapters/analyzers/sandbox.py`

## Test evidence

- `tests/unit/test_bundle_lock.py`
- `tests/unit/test_analyzer_argv.py`
