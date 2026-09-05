# Current state

SecureMail is an offline, deterministic-first analyzer of SMTP, IMAP, and POP3
traffic in PCAP/PCAPNG files. It scores and deduplicates findings, publishes
coverage denominators, exports forensic reports in JSON, HTML, and PDF, can run
a shadow-mode advisory ML stage, and exposes canonical reports through FastAPI
and a React dashboard that can analyze PCAP/PCAPNG captures offline.

Python orchestrates. Zeek is the primary packet engine. A bounded TShark pass
corroborates mail command/status and TLS handshake message frames when the first
Zeek pass shows mail, implicit-TLS, or any `ssl.log` UID.

## What is live

Use cases in
[`src/securemail/application/run_analysis.py`](../src/securemail/application/run_analysis.py),
wired through [`src/securemail/bootstrap.py`](../src/securemail/bootstrap.py):

- `securemail analyze` — PCAP/PCAPNG → v2 `EvidenceDocument`
- `securemail score` — synthetic finding JSON → `PostureAssessment` on stdout
- `securemail report` — canonical report JSON → RFC 8785 JSON, HTML, and PDF
- `securemail evaluate-ml` — seeded cohort directory → detection-delay / precision@K gates
- FastAPI + React — catalog preview, PCAP/PCAPNG upload, HTML/PDF download

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
plus `tests/fixtures/synthetic_findings/` for Step 8 and
`tests/fixtures/reports/` for Step 9, and multi-case canonical reports under
`tests/fixtures/dashboard/` for Step 11. The harness in
[`tests/support/fixture_harness.py`](../tests/support/fixture_harness.py)
runs the real CLI and diffs analyze/score output against `expected.json` (no
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
| 9 | Canonical JSON → HTML/PDF | **Done** |
| 10 | Advisory ML | **Done** (`evaluate-ml`, `--advisory`, baseline + gated Isolation Forest) |
| 11 | FastAPI + React | **Done** (byte-identical API, case isolation, Playwright dashboard) |
| Post-11 | Offline capture upload dashboard | **Done** (PCAP intake, worker, HTML/PDF, ML history) |

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

# Step 9 — canonical JSON → HTML/PDF from one in-memory object
uv run securemail report tests/fixtures/reports/golden_report.json --format json,html,pdf --out out/

# Step 10 — advisory ML evaluation harness (baseline + Isolation Forest gates)
uv run securemail evaluate-ml tests/support/synthetic_cohorts/cohort_seeded_v1/

# Step 11 — API/CLI contract plus browser workflows
SECUREMAIL_DATA_ROOT=out/data SECUREMAIL_REPORT_ROOT=out/data \
  SECUREMAIL_START_WORKER=1 \
  uv run uvicorn securemail.api.main:app
npm --prefix frontend run test:e2e
```

Analyze `--out` is required. Output is JSON with sorted keys, 2-space indent, a
trailing newline, and `ensure_ascii=False`. `--policy-profile` defaults to
`ietf_current`. Unknown profiles exit 2. A malformed pack or missing capture
start time for `historical_at_capture` exits 1. `score` writes that same JSON
style to stdout; invalid/oversized input exits 1.

The dashboard can assemble a canonical report from analyze output automatically
after a capture upload; `securemail report` still accepts an already assembled
`securemail.report/v1` object.

## CLI that exists vs files that do not run

[`src/securemail/api/cli/main.py`](../src/securemail/api/cli/main.py) registers
**`analyze`, `score`, `report`, and `evaluate-ml`**. `api/cli/commands/analyze.py`
is a leftover Step 0 stub; the live analyze command is in `main.py`.

## Not in this build

The analyze JSON does **not** embed a report manifest when emitted by
`securemail analyze`. The dashboard worker and `assemble_report` wrap that
document for HTML/PDF. Pass/present policy outcomes are serialized as
`policy_checks`, not as `Finding` records. Revocation without
imported OCSP/CRL is `unknown`. `run_identity.policy_pack_version` is the
SHA-256 of the canonical validated pack JSON.
`run_identity.trust_store_digest` is the SHA-256 of the pinned PEM snapshot. No
network calls happen during analysis (analyzer containers use `--network=none`;
chain validation does not fetch AIA/OCSP/CRL/CT/DNS). There is no PostgreSQL
control plane or queue in this step. Capture jobs use a bounded filesystem
store and a local worker process.

See [architecture.md](architecture.md) for the live module map,
[scoring.md](scoring.md) for the v1 formula, [reports.md](reports.md) for
HTML/PDF, [advisory-ml.md](advisory-ml.md) for Step 10, and
[dashboard.md](dashboard.md) for Step 11.
