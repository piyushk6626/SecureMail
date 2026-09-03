# Current state

SecureMail is a **CLI-only**, offline, deterministic analyzer of SMTP, IMAP, and
POP3 traffic in PCAP/PCAPNG files. It does not yet score findings, render
HTML/PDF, run ML, or expose an API.

Python orchestrates. Zeek is the primary packet engine. A bounded TShark pass
corroborates mail command/status and TLS ClientHello frame numbers when the
first Zeek pass shows mail or implicit-TLS evidence.

## What is live

The one use case is `run_analysis` in
[`src/securemail/application/run_analysis.py`](../src/securemail/application/run_analysis.py),
wired through [`src/securemail/bootstrap.py`](../src/securemail/bootstrap.py) to
the Typer command `securemail analyze`.

It produces a frozen v0 JSON document with:

- run identity (capture hash, analyzer-bundle digest, configuration digest)
- capinfos preflight
- per-flow TCP reconstruction quality
- per-session protocol identity and STARTTLS/STLS / implicit-TLS assessment

There are **40** committed fixtures under `tests/fixtures/<case_id>/`. The
harness in [`tests/support/fixture_harness.py`](../tests/support/fixture_harness.py)
runs the real CLI and diffs the entire output against `expected.json` (no
ignored fields).

## Step map

| Step | Owns | Status |
|---|---|---|
| 0 | Layout, sandbox runners, v0 schema, fixture harness, analyzer lockfile | **Done** |
| 1 | TCP reconstruction quality | **Done** |
| 2 | SMTP/IMAP/POP3 identification (`port_hint` ≠ `payload_evidence`) | **Done** |
| 3 | STARTTLS/STLS state machines + implicit TLS | **Done** |
| 4 | TLS version / cipher / key exchange | Placeholder (`domain/evidence/handshake.py`, `domain/policies/tls/key_exchange.py`, IANA snapshot loader) |
| 5 | Certificate facts | Placeholder (`domain/evidence/certificate.py`, `pki/key_strength.py`, certificate store) |
| 6 | Chain + identity (offline trust store) | Placeholder (PKI adapters and `trust-store-snapshot.pem`) |
| 7 | Versioned rule packs + forward secrecy | Placeholder (`rule_engine.py`, YAML packs, `forward_secrecy.py`) |
| 8 | Scoring, dedup, coverage denominators | Placeholder (`domain/findings/*`, `api/cli/commands/score.py`) |
| 9 | Canonical JSON → HTML/PDF | Placeholder (report adapters/templates, `report.py`) |
| 10 | Advisory ML | Placeholder (`advisory_pipeline.py`, `evaluate_ml.py`, baselines) |
| 11 | FastAPI + React | Placeholder (`api/main.py`, routers, `frontend/` README only) |

The *why* and the remaining contracts live in
[`plans/build_plan.md`](../plans/build_plan.md). This page only records what the
repository actually runs.

## Proof commands

Each completed step has a named CLI proof (plus the rest of that step’s
fixtures in `make test`):

```bash
# Step 0 — empty capture, schema-valid reproducible JSON
uv run securemail analyze tests/fixtures/empty/capture.pcapng --out out/empty.json

# Step 1 — snaplen truncation is incomplete, never silently complete
uv run securemail analyze tests/fixtures/tcp_snaplen_truncation/capture.pcapng --out out/tcp.json

# Step 2 — POP3 identified from payload on a nonstandard port
uv run securemail analyze tests/fixtures/pop3_nonstandard_port/capture.pcapng --out out/pop3.json

# Step 3 — IMAP STARTTLS accepted after stripped capability; downgrade_consistent
uv run securemail analyze tests/fixtures/imap_starttls_capability_stripped/capture.pcapng --out out/imap.json
```

`--out` is required. Output is JSON with sorted keys, 2-space indent, a trailing
newline, and `ensure_ascii=False`.

## CLI that exists vs files that do not run

[`src/securemail/api/cli/main.py`](../src/securemail/api/cli/main.py) registers
**`analyze` only**. These files exist as Step N stubs and are **not** wired:

- `api/cli/commands/analyze.py` — leftover Step 0 stub; the live command is in `main.py`
- `api/cli/commands/score.py` — Step 8
- `api/cli/commands/report.py` — Step 9
- `api/cli/commands/evaluate_ml.py` — Step 10

`securemail score`, `securemail report`, and `securemail evaluate-ml` are not
commands.

## Not in this build

The JSON does **not** contain `TlsHandshake`, `CertificateEvidence`, `Finding`,
posture scores, or a report manifest. `run_identity.policy_pack_version` and
`run_identity.trust_store_digest` are always `null`. No network calls happen
during analysis (analyzer containers use `--network=none`). No dashboard, no
Postgres, no queue.

See [architecture.md](architecture.md) for the live module map and
[fixtures.md](fixtures.md) for every committed case.
