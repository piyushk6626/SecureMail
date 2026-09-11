---
status: current
audience: user
authoritative_for: Implemented capabilities after Steps 0–11
last_verified: 2026-09-11
---

# Current capabilities

SecureMail is an offline, deterministic-first analyzer of SMTP, IMAP, and
POP3 traffic in PCAP/PCAPNG files. Python orchestrates. Zeek is the primary
packet engine. A bounded TShark pass corroborates mail command/status and TLS
handshake frames when needed.

All of the following are **Implemented** (present in source and covered by a
test or CLI proof).

## CLI

- `securemail analyze` — PCAP/PCAPNG → v2 `EvidenceDocument`
- `securemail score` — synthetic finding JSON → `PostureAssessment` on stdout
- `securemail report` — canonical report JSON → RFC 8785 JSON, HTML, and PDF
- `securemail evaluate-ml` — seeded cohort directory → detection-delay /
  precision@K gates

Commands, options, and examples: [CLI](../reference/cli.md).

## Pipeline

- Intake hash, capinfos preflight, sandboxed Zeek, optional TShark
- TCP reconstruction quality (`complete` / `incomplete` / `conflicting`)
- Payload-driven protocol ID (`port_hint` ≠ `payload_evidence`)
- STARTTLS/STLS state machines and implicit-TLS ALPN correlation
- TLS version / IANA cipher / version-aware key exchange
- Per-certificate facts; leaf chain validation; RFC 9525 identity
- Versioned YAML packs; forward secrecy; scoring; coverage denominators
- Advisory ML after the deterministic baseline (`--advisory` off by default)

**71** PCAP fixture directories plus synthetic scoring, report goldens,
dashboard catalog fixtures, and the ML cohort.

## Dashboard

FastAPI + React workbench over the same canonical JSON. Browser-local preview
or a bounded filesystem catalog; PCAP/PCAPNG upload on a single host with an
out-of-process worker. Every case starts with assessment trust, coverage,
limitations, and provenance before the endpoint-first finding tree. The score
is labelled **Highest endpoint priority**, never overall system health.
Coverage is a zero-filled protocol × category matrix with a canonical
policy-check ledger. Finding detail exposes all six score addends,
occurrences, qualified/derived evidence references, frame context, and same-UID
lineage. Session, TLS-handshake, and certificate review stay in separate
observed-fact views. Four labelled regions remain: observed facts,
deterministic conclusions, advisory/ML, and analyst conclusions.

HTTP routes: [API](../reference/api.md).

## Proof commands

```bash
uv run securemail analyze tests/fixtures/empty/capture.pcapng --out out/empty.json
uv run securemail analyze tests/fixtures/tcp_snaplen_truncation/capture.pcapng --out out/tcp.json
uv run securemail analyze tests/fixtures/pop3_nonstandard_port/capture.pcapng --out out/pop3.json
uv run securemail analyze tests/fixtures/imap_starttls_capability_stripped/capture.pcapng --out out/imap.json
uv run securemail analyze tests/fixtures/tls13_hello_retry_request/capture.pcapng --out out/tls13-hrr.json
uv run securemail analyze tests/fixtures/cert_expired_rsa1024/capture.pcapng --out out/cert.json
uv run securemail analyze tests/fixtures/cert_chain_san_mismatch/capture.pcapng --out out/chain.json
uv run securemail analyze tests/fixtures/tls13_psk_only_resumption/capture.pcapng \
  --policy-profile ietf_current --out out/policy.json
uv run securemail score tests/fixtures/synthetic_findings/mixed_severity.json
uv run securemail report tests/fixtures/reports/golden_report.json --format json,html,pdf --out out/
uv run securemail evaluate-ml tests/support/synthetic_cohorts/cohort_seeded_v1/
```

## Related pages

- [Known limitations](known-limitations.md)
- [Compatibility matrix](compatibility-matrix.md)
- [Evidence schema](../reference/evidence-schema.md)

## Implementation anchors

- `src/securemail/application/run_analysis.py`
- `src/securemail/bootstrap.py`
- `src/securemail/api/main.py`

## Test evidence

- Fixture harness + Playwright `tests/e2e/dashboard.spec.ts`
