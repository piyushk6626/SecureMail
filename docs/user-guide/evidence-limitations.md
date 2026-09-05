---
status: current
audience: user
authoritative_for: honest evidence gaps that must not be read as passes
last_verified: 2026-09-06
---

# Evidence limitations

Missing, truncated, or encrypted-after-handshake evidence is recorded with a
state, not repaired. Do not treat gaps as “checks passed.”

The report `limitations` object and the dashboard “Limitations are not
passes” card surface truncated packets, incomplete/conflicting flow counts,
not-observable certificate counts, and unknown / not-observable policy-check
counts.

## Capture quality

| Situation | What you should see |
|---|---|
| Snaplen shorter than original packets | `truncated_packets_present`; flows `incomplete` / `snaplen_truncation`; never silently `complete`. |
| Missing TCP bytes / unclear boundaries | `reconstruction_quality=incomplete`. |
| Overlapping retransmission conflict | `conflicting`, with competing ranges retained. |
| Empty or non-mail capture | Preflight and run identity; no sessions. Not a secure posture. |

The original file is hashed at intake. Analyzers run on working copies.
Evidential originals are not rewritten.

## Protocol identity

Ports are hints. Ambiguous banners are `indeterminate`, not a guess.
Zeek vs TShark disagreement is `conflicting` with
`identification_confidence=0.5`. Nonstandard-port POP3 can be
`payload_evidence=pop3` with `port_hint=none`.

## STARTTLS / implicit TLS

`downgrade_consistent` is not proof of an attacker. Implicit TLS on 465/993/995
without selected ALPN is `indeterminate`, not “this is IMAP because the port
said so.” Implicit TLS not on those ports is `not_observable` for that
correlation.

## TLS 1.3 certificates

TLS 1.3 certificates after `ServerHello` are `not_observable` unless history
letter `x` is present (or authorized secrets/telemetry exist — this build has
no such import path). Do not fabricate them from `x509.log`. Handshake
`CertificateVerify` without letter `y` is `not_observable`.

A truncated handshake that stops after ClientHello has
`version.selected=null` and `evidence_state=incomplete`.

## Encrypted Client Hello / SNI

ECH can hide SNI. Missing SNI and missing `--expected-hostname` make
`identity_match` `null`, not a pass. RFC 9525 SAN matching has **no CN
fallback**.

## Revocation and enrichment

Analysis workers do not fetch AIA, OCSP, CRL, CT, DNS, MTA-STS, models, or
telemetry (`--network=none` on analyzer containers). Revocation is `unknown`.
Enrichment that is not imported, hashed, and retained as evidence is out of
scope.

The host Python process is **not** OS-network-sandboxed. Offline operation
depends on an air-gapped host or operational controls. See
[air-gapped operation](../operations/air-gapped-operation.md).

## Policy and scoring honesty

- `historical_at_capture` without `capture_start_time` fails closed.
- Coverage `unknown` / `not_observable` are first-class denominators.
- `risk_score` is `null` when there are no findings and coverage is incomplete.
- Advisory `ADVISORY_INSUFFICIENT_HISTORY` is not “no anomaly.”

## Forward secrecy claims this tool will not make

From one PCAP, SecureMail will not claim ephemeral-key reuse or ticket
rotation. TLS 1.3 PSK-only resumption is indeterminate for forward secrecy,
not “present.”

## Related pages

- [Interpret evidence](interpret-evidence.md)
- [Scoring and coverage](scoring-and-coverage.md)
- [Advisory ML](advisory-ml.md)
- [As-built evidence model](../reference/evidence-schema.md)

## Implementation anchors

- `src/securemail/application/assemble_report.py`
- `src/securemail/domain/evidence/run.py`
- `src/securemail/domain/policies/pki/identity.py`

## Test evidence

- `tests/test_tcp_fixtures.py`
- `tests/unit/test_truncated_stream_never_complete.py`
- `tests/fixtures/tls13_psk_only_resumption/`
- `tests/fixtures/reports/golden_report.json`
