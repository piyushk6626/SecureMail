---
status: current
audience: architect
authoritative_for: seven evidence-state semantics
last_verified: 2026-09-06
---

# 0004. Evidence-state semantics

Date: 2026-09-06 (retrospective)
Status: accepted
Steps: 0–7 (vocabulary); enforced in fixtures through Step 11

## Question

How should SecureMail represent visibility when a capture does not contain a
fact, contains a partial fact, or contains disagreement?

## Decision

Define **seven** states once as `EvidenceState` in `domain/evidence/run.py`.
Every applicable field uses exactly:

`observed`, `verified`, `inferred`, `incomplete`, `conflicting`,
`not_observable`, `indeterminate`.

**Missing evidence is not a pass.** `not_observable`, `incomplete`, and
`indeterminate` must never be treated as “no weakness detected” or “secure”.
Coverage publishes `unknown_count` and `not_observable_count` instead of
folding them into `passed_count`.

`not_observable` includes **protocol-hidden** facts, not only “check does not
apply”:

- TLS 1.3 certificates after `ServerHello` (encrypted) unless history letter
  `x` is present or authorized secrets/telemetry exist
- No STARTTLS/STLS attempt
- Implicit-TLS correlation when the flow is not on 465/993/995 and no
  selected ALPN

Do not fabricate TLS 1.3 certificate records from `x509.log` when the
handshake did not observe them.

`verified` is reserved on classifiers; negative findings use it as
`evaluation_state`.

## Why

Passive PCAP cannot see everything. Honest states keep policy, scoring, HTML,
and the dashboard from implying a clean bill of health when the capture was
truncated, conflicting, or encrypted past the observable handshake.

## Consequences

- Fixture tests assert the state field itself.
- Scoring confidence for `not_observable` is 0 points; the check still
  appears in denominators.
- HTML/UI must label states (`OBS` / `NOB` / …) rather than color-only.
- ECH can hide SNI; missing reference identity leaves `identity_match` null.

Full table: [evidence states](../reference/evidence-states.md).

## Related pages

- [Evidence schema](../reference/evidence-schema.md)
- [Scoring](../user-guide/scoring-and-coverage.md)
- [Threat model](../security/threat-model.md)

## Implementation anchors

- `src/securemail/domain/evidence/run.py`
- `src/securemail/domain/findings/posture.py`
- `src/securemail/application/normalize_certificates.py`

## Test evidence

- `tests/unit/test_evidence_state.py`
- `tests/unit/test_posture.py`
- `tls13_full_handshake` fixture (`server_certificate_state=not_observable`)
