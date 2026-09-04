# SecureMail

Offline, deterministic-first cryptographic posture analysis for SMTP, IMAP, and
POP3 traffic captured in PCAP/PCAPNG files.

This repository has completed **Steps 0–4** of `plans/build_plan.md`: package
layout, sandboxed Zeek/TShark runners, TCP reconstruction quality, payload-driven
protocol identification, STARTTLS/STLS plus implicit-TLS assessment, and TLS
version / cipher / key-exchange evidence. The live command is `securemail
analyze`. Steps 5–11 remain named placeholders.

**As-built documentation** (what the code does today) lives in
[`docs/README.md`](docs/README.md). Plan contracts (what to build next) remain in
`plans/`.

## Prerequisites

See `plans/PROJECT_SCAFFOLD.md` Section 2. In short: Homebrew `uv`, CPython 3.13
(via `uv`, not system Python), git-lfs, Docker Desktop, Homebrew OpenSSL 3, and
Pango (needed by WeasyPrint at Step 9; `make doctor` checks it now).

## Bootstrap

```bash
git lfs install
uv sync --extra dev
docker pull zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3
make tshark-image
make zeek-image
make doctor
make lint
make test
uv run securemail analyze tests/fixtures/empty/capture.pcapng --out out/empty.json
```

On macOS, `make sync` and `make doctor` set `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`
so the uv-managed interpreter can load Homebrew Pango. Do not `brew install weasyprint`.

## Proof commands (completed steps)

```bash
# Step 0 — empty capture
uv run securemail analyze tests/fixtures/empty/capture.pcapng --out out/empty.json

# Step 1 — TCP reconstruction (snaplen truncation is incomplete)
uv run securemail analyze tests/fixtures/tcp_snaplen_truncation/capture.pcapng --out out/tcp.json

# Step 2 — protocol ID from payload on a nonstandard port
uv run securemail analyze tests/fixtures/pop3_nonstandard_port/capture.pcapng --out out/pop3.json

# Step 3 — STARTTLS after stripped capability (`downgrade_consistent`)
uv run securemail analyze tests/fixtures/imap_starttls_capability_stripped/capture.pcapng --out out/imap.json

# Step 4 — TLS 1.3 HelloRetryRequest, version/cipher/key-exchange evidence
uv run securemail analyze tests/fixtures/tls13_hello_retry_request/capture.pcapng --out out/tls13-hrr.json
```

`--out` is required. Output is a v0 `EvidenceDocument` JSON file (flows,
sessions, and top-level `handshakes`). There is no `score`, `report`, or
`evaluate-ml` command yet.

## Layout

Clean architecture, enforced by import-linter:

- `src/securemail/api/cli/` — Typer CLI (FastAPI placeholders until Step 11)
- `src/securemail/application/` — use cases
- `src/securemail/domain/` — pure Pydantic models and rules
- `src/securemail/ports/` — `typing.Protocol` interfaces
- `src/securemail/adapters/` — Zeek/TShark runners and later I/O
- `src/securemail/bootstrap.py` — the only composition root

See [`docs/architecture.md`](docs/architecture.md) for the live module map and
[`docs/current-state.md`](docs/current-state.md) for done vs placeholder.
