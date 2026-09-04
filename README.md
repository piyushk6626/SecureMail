# SecureMail

Offline, deterministic-first cryptographic posture analysis for SMTP, IMAP, and
POP3 traffic captured in PCAP/PCAPNG files.

This repository has completed **Steps 0–11** of `plans/build_plan.md`: package
layout, sandboxed Zeek/TShark runners, TCP reconstruction quality, payload-driven
protocol identification, STARTTLS/STLS plus implicit-TLS assessment, TLS
version / cipher / key-exchange evidence, per-certificate facts, offline
chain validation with RFC 9525 identity matching, versioned rule packs,
forward-secrecy assessment, posture scoring with coverage denominators,
canonical JSON → HTML/PDF reports, and advisory ML after the deterministic
baseline. The live commands are `securemail analyze`, `securemail score`,
`securemail report`, and `securemail evaluate-ml`; FastAPI and the React
dashboard present the same canonical report contract.

**As-built documentation** (what the code does today) lives in
[`docs/README.md`](docs/README.md). Plan contracts (what to build next) remain in
`plans/`.

## Prerequisites

See `plans/PROJECT_SCAFFOLD.md` Section 2. In short: Homebrew `uv`, CPython 3.13
(via `uv`, not system Python), git-lfs, Docker Desktop, Homebrew OpenSSL 3, and
Pango (needed by WeasyPrint for PDF), plus Node 22.12+ through the
`frontend/.nvmrc` pin. `make doctor` checks these prerequisites.

## Bootstrap

```bash
git lfs install
uv sync --extra dev --extra reports --extra ml --extra api
cd frontend && nvm use && npm ci && cd ..
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

# Step 5 — expired RSA-1024 certificate facts (not a finding)
uv run securemail analyze tests/fixtures/cert_expired_rsa1024/capture.pcapng --out out/cert.json

# Step 6 — SAN mismatch with a still-valid path
uv run securemail analyze tests/fixtures/cert_chain_san_mismatch/capture.pcapng --out out/chain.json

# Step 7 — TLS 1.3 PSK-only resumption; forward secrecy is indeterminate
uv run securemail analyze tests/fixtures/tls13_psk_only_resumption/capture.pcapng --policy-profile ietf_current --out out/policy.json

# Step 8 — posture score, dedup, coverage denominators
uv run securemail score tests/fixtures/synthetic_findings/mixed_severity.json

# Step 9 — canonical JSON → HTML/PDF
uv run securemail report tests/fixtures/reports/golden_report.json --format json,html,pdf --out out/

# Step 10 — advisory ML evaluation harness
uv run securemail evaluate-ml tests/support/synthetic_cohorts/cohort_seeded_v1/

# Step 11 — FastAPI + React dashboard
SECUREMAIL_REPORT_ROOT=tests/fixtures/dashboard uv run uvicorn securemail.api.main:app
# In another terminal:
npm --prefix frontend run dev
npm --prefix frontend run test:e2e
```

`analyze --out` is required. Analyze output is a v2 `EvidenceDocument` JSON file
(flows, sessions, handshakes, certificates, session-level findings, policy
checks, and posture). `score` writes the same posture object to stdout.
`report` reads a `securemail.report/v1` object and writes RFC 8785 JSON, HTML,
and PDF from one in-memory dump. `evaluate-ml` scores the locked synthetic
cohort and prints detection-delay / precision@K gates. `report --advisory`
fills the Advisory / ML section without changing deterministic findings.

## Layout

Clean architecture, enforced by import-linter:

- `src/securemail/api/` — Typer CLI plus thin FastAPI report routes
- `src/securemail/application/` — use cases
- `src/securemail/domain/` — pure Pydantic models and rules
- `src/securemail/ports/` — `typing.Protocol` interfaces
- `src/securemail/adapters/` — Zeek/TShark runners and concrete offline I/O
- `src/securemail/bootstrap.py` — the only composition root

See [`docs/architecture.md`](docs/architecture.md) for the live module map and
[`docs/current-state.md`](docs/current-state.md) for done vs placeholder.
