# Current state

SecureMail is a **CLI-only**, offline, deterministic analyzer of SMTP, IMAP, and
POP3 traffic in PCAP/PCAPNG files. It scores and deduplicates findings and
publishes coverage denominators. It does not yet render HTML/PDF, run ML, or
expose an API.

Python orchestrates. Zeek is the primary packet engine. A bounded TShark pass
corroborates mail command/status and TLS handshake message frames when the first
Zeek pass shows mail, implicit-TLS, or any `ssl.log` UID.

## What is live

Use cases in
[`src/securemail/application/run_analysis.py`](../src/securemail/application/run_analysis.py),
wired through [`src/securemail/bootstrap.py`](../src/securemail/bootstrap.py):

- `securemail analyze` — PCAP/PCAPNG → v2 `EvidenceDocument`
- `securemail score` — synthetic finding JSON → `PostureAssessment` on stdout

Analyze produces a frozen v2 JSON document with:

- run identity (capture hash, analyzer-bundle digest, configuration digest,
  analysis time, policy profile, policy-pack SHA-256)
- capinfos preflight, including canonical UTC `capture_start_time`
- per-flow TCP reconstruction quality
- per-session protocol identity and STARTTLS/STLS / implicit-TLS assessment
- top-level TLS handshake evidence (version, IANA cipher, version-aware key
  exchange, `ssl_history`, frame-linked messages, CertificateVerify algorithm)
- top-level certificate facts (DER SHA-256, subject/issuer, validity window,
  public-key algorithm and effective strength, certificate signature algorithm)
- leaf-only chain validation and RFC 9525 identity matching against a pinned
  offline trust snapshot
- deterministic session-level `Finding` records from a versioned YAML rule pack
  (negative and indeterminate outcomes only)
- applicable `policy_checks` (pass/fail/unknown/not_observable) and a posture
  summary (prioritized endpoint findings, coverage denominators, risk score)

There are **71** PCAP fixture directories under `tests/fixtures/<case_id>/`
plus `tests/fixtures/synthetic_findings/` for Step 8. The harness in
[`tests/support/fixture_harness.py`](../tests/support/fixture_harness.py)
runs the real CLI and diffs the entire output against `expected.json` (no
ignored fields). Optional `analyze.json` supplies `--analysis-time`,
`--expiry-warning-days`, `--expected-hostname`, and `--policy-profile`. When
`analysis_time` is omitted, the harness pins `2026-09-04T12:00:00Z` so goldens
stay stable; the live CLI still defaults analysis time to now.

## Step map

| Step | Owns | Status |
|---|---|---|
| 0 | Layout, sandbox runners, schema, fixture harness, analyzer lockfile | **Done** |
| 1 | TCP reconstruction quality | **Done** |
| 2 | SMTP/IMAP/POP3 identification (`port_hint` ≠ `payload_evidence`) | **Done** |
| 3 | STARTTLS/STLS state machines + implicit TLS | **Done** |
| 4 | TLS version / cipher / key exchange | **Done** |
| 5 | Certificate facts | **Done** |
| 6 | Chain + identity (offline trust store) | **Done** |
| 7 | Versioned rule packs + forward secrecy | **Done** |
| 8 | Scoring, dedup, coverage denominators | **Done** |
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

# Step 4 — TLS 1.3 HelloRetryRequest; version/cipher/key-exchange evidence
uv run securemail analyze tests/fixtures/tls13_hello_retry_request/capture.pcapng --out out/tls13-hrr.json

# Step 5 — expired RSA-1024 certificate facts (not a finding)
uv run securemail analyze tests/fixtures/cert_expired_rsa1024/capture.pcapng --out out/cert.json

# Step 6 — SAN mismatch with a still-valid path
uv run securemail analyze tests/fixtures/cert_chain_san_mismatch/capture.pcapng --out out/chain.json

# Step 7 — TLS 1.3 PSK-only resumption; forward secrecy is indeterminate
uv run securemail analyze tests/fixtures/tls13_psk_only_resumption/capture.pcapng --policy-profile ietf_current --out out/policy.json

# Step 8 — mixed severity score vectors, named components, analyst order
uv run securemail score tests/fixtures/synthetic_findings/mixed_severity.json
```

Analyze `--out` is required. Output is JSON with sorted keys, 2-space indent, a
trailing newline, and `ensure_ascii=False`. `--policy-profile` defaults to
`ietf_current`. Unknown profiles exit 2. A malformed pack or missing capture
start time for `historical_at_capture` exits 1. `score` writes that same JSON
style to stdout; invalid/oversized input exits 1.

## CLI that exists vs files that do not run

[`src/securemail/api/cli/main.py`](../src/securemail/api/cli/main.py) registers
**`analyze` and `score`**. These files exist as Step N stubs and are **not**
wired:

- `api/cli/commands/analyze.py` — leftover Step 0 stub; the live command is in `main.py`
- `api/cli/commands/report.py` — Step 9
- `api/cli/commands/evaluate_ml.py` — Step 10

`securemail report` and `securemail evaluate-ml` are not commands.

## Not in this build

The JSON does **not** contain a report manifest. Pass/present policy outcomes
are serialized as `policy_checks`, not as `Finding` records. Revocation without
imported OCSP/CRL is `unknown`. `run_identity.policy_pack_version` is the
SHA-256 of the canonical validated pack JSON.
`run_identity.trust_store_digest` is the SHA-256 of the pinned PEM snapshot. No
network calls happen during analysis (analyzer containers use `--network=none`;
chain validation does not fetch AIA/OCSP/CRL/CT/DNS). No dashboard, no Postgres,
no queue.

See [architecture.md](architecture.md) for the live module map,
[scoring.md](scoring.md) for the v1 formula, and [fixtures.md](fixtures.md) for
every committed case.
