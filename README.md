# SecureMail

Offline, deterministic-first cryptographic posture analysis for SMTP, IMAP, and
POP3 traffic captured in PCAP/PCAPNG files.

This repository is at **Step 0** of `plans/build_plan.md`: package layout, sandboxed
Zeek/TShark runners, the v0 evidence schema, and one empty-capture fixture. Later
steps fill the named files in `plans/PROJECT_SCAFFOLD.md`; they do not invent new
top-level layout.

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

## Layout

Clean architecture, enforced by import-linter:

- `src/securemail/api/cli/` — Typer CLI (FastAPI placeholders until Step 11)
- `src/securemail/application/` — use cases
- `src/securemail/domain/` — pure Pydantic models and rules
- `src/securemail/ports/` — `typing.Protocol` interfaces
- `src/securemail/adapters/` — Zeek/TShark runners and later I/O
- `src/securemail/bootstrap.py` — the only composition root
