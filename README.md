# SecureMail

Offline, deterministic-first cryptographic posture analysis for SMTP, IMAP, and
POP3 traffic captured in PCAP/PCAPNG files.

Python orchestrates. Zeek is the primary packet engine. A bounded TShark pass
corroborates mail and TLS handshake frames. Policy, scoring, reports, and the
optional advisory ML stage run after that deterministic baseline.

The named build plan (Steps 0–11 plus capture upload) is **complete**. Live
behavior is documented in [`docs/README.md`](docs/README.md). Historical
contracts live under [`plans/`](plans/README.md) as provenance, not as “what to
build next”.

## Documentation by audience

| If you are… | Start here |
|---|---|
| Installing and running the CLI | [Getting started](docs/getting-started/README.md) |
| Interpreting findings | [User guide](docs/user-guide/README.md) |
| Operating the local API/worker | [Operations](docs/operations/README.md) |
| Changing code or fixtures | [Contributing](CONTRIBUTING.md) |
| Reviewing architecture | [System context](docs/architecture/system-context.md) |
| Reviewing security | [Threat model](docs/security/threat-model.md) |

## Prerequisites

Apple Silicon macOS with Homebrew at `/opt/homebrew` is the primary
workstation. Ubuntu is CI-validated. Windows and Intel macOS `/usr/local`
Homebrew are unsupported. Details:
[supported platforms](docs/getting-started/supported-platforms.md).

In short: `uv` + CPython 3.13, git-lfs, Docker, Homebrew OpenSSL 3, Pango
(WeasyPrint), Node 22 via `frontend/.nvmrc`. `make doctor` checks these.

## Bootstrap

```bash
git lfs install
git lfs pull
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

On macOS, `make sync` and `make doctor` set
`DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`. Do not `brew install weasyprint`.

Full install: [macOS](docs/getting-started/macos-apple-silicon.md) or
[Linux](docs/getting-started/linux.md).

## Commands

```bash
uv run securemail analyze tests/fixtures/empty/capture.pcapng --out out/empty.json
uv run securemail score tests/fixtures/synthetic_findings/mixed_severity.json
uv run securemail report tests/fixtures/reports/golden_report.json --format json,html,pdf --out out/
uv run securemail evaluate-ml tests/support/synthetic_cohorts/cohort_seeded_v1/

SECUREMAIL_DATA_ROOT=out/data SECUREMAIL_REPORT_ROOT=out/data \
  SECUREMAIL_START_WORKER=1 \
  uv run uvicorn securemail.api.main:app
npm --prefix frontend run dev
```

`analyze` writes a v2 `EvidenceDocument`. `report` reads an already assembled
`securemail.report/v1` object. The dashboard worker is the path that assembles
analyze output into a report after an upload. Options:
[CLI reference](docs/reference/cli.md).

## Layout

Clean architecture, enforced by import-linter:

- `src/securemail/api/` — Typer CLI plus thin FastAPI routes
- `src/securemail/application/` — use cases
- `src/securemail/domain/` — pure Pydantic models and rules
- `src/securemail/ports/` — `typing.Protocol` interfaces
- `src/securemail/adapters/` — Zeek/TShark runners and concrete offline I/O
- `src/securemail/bootstrap.py` — the only composition root

See [clean architecture](docs/architecture/clean-architecture.md) and
[current capabilities](docs/status/current-capabilities.md).
