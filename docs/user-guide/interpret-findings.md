---
status: current
audience: user
authoritative_for: Finding records versus evidence facts
last_verified: 2026-09-06
---

# Interpret findings

A `Finding` is a **session-level policy judgment**. It does not mutate flows,
sessions, handshakes, or certificates. Advisory ML never edits this array.

Only **negative** and **indeterminate** rule outcomes are serialized as
findings. Passes stay in `policy_checks`. “TLS 1.3 with (EC)DHE and a valid
path” does not produce a finding.

## Fields to read first

| Field | Meaning |
|---|---|
| `code` | Stable rule id (`TLS_NEGOTIATED_TLS10`, `TLS_FORWARD_SECRECY_ABSENT`, `NIST_TLS_SUITE_NOT_APPROVED`, …). |
| `outcome` | `negative` or `indeterminate`. |
| `severity` | `high` / `medium` / `low` / `informational` from the pack. Built-in YAML currently emits `high`, `medium`, and `informational`; `low` exists for scoring fixtures. |
| `basis_state` | Weakest contributing evidence state. Drives the confidence addend in scoring. |
| `evaluation_state` | `verified` for negative outcomes; `indeterminate` for indeterminate outcomes. This is not packet-level `verified`. |
| `policy_profile` / `policy_pack_version` | Pack that produced the finding. Mixed packs are not merged at dedup. |
| `policy_evaluation_time` | Analysis time, or capture start for `historical_at_capture`. |
| `rule_effective_from` / `rule_effective_until` | Inclusive start; exclusive end when set. |
| `rationale` / `standards` | Why the rule fired and which RFC/NIST sections the YAML cites. |
| `evidence_references` | Canonical pointers (uid / record key). Not JSON array indexes. |
| `finding_id` | SHA-256 of capture hash, profile, pack digest, rule id, outcome, target, record key. |

## Facts vs findings

| Observation | Layer |
|---|---|
| Certificate public key is RSA-1024 | Certificate evidence (`public_key_size`, `effective_strength_bits`) |
| That key is a policy failure | Finding `CERT_RSA_KEY_LT2048` / `CERT_PUBLIC_KEY_STRENGTH_LT112` when the pack says so |
| TLS 1.3 PSK-only resumption | Handshake key-exchange fact `PSK` |
| Forward secrecy cannot be claimed | Finding `TLS_FORWARD_SECRECY_INDETERMINATE` |
| Suite not in SP 800-52 tables | Finding `NIST_TLS_SUITE_NOT_APPROVED` under `nist_federal` only |

Forward secrecy assessment (consumed by YAML, not guessed from cipher names
on TLS 1.3):

- TLS 1.2 ECDHE/DHE → present (no finding)
- Static RSA/DH/ECDH → absent (`TLS_FORWARD_SECRECY_ABSENT`)
- TLS 1.3 (EC)DHE → present
- TLS 1.3 PSK-only or missing handshake → indeterminate

Present outcomes are not emitted as findings. One PCAP cannot prove ephemeral
key reuse or ticket rotation; SecureMail never claims those.

## Where findings appear

- `evidence.findings` — session-level records from `analyze`
- `evidence.posture.prioritized_findings` — endpoint-deduped, scored, ordered
- Report HTML/PDF **Deterministic Conclusions**
- Dashboard region **Deterministic Conclusions** (filterable table)

Dedup collapses session findings that share
`(code, affected_endpoint, policy_profile, policy_pack_version)` without
dropping contributing session references. See
[scoring and coverage](scoring-and-coverage.md).

## Dashboard and reports

Unknown, incomplete, indeterminate, and not-observable evidence stay labeled.
They are never presented as passes. Hostile strings in titles, rationales, and
banners render as forensic text.

Analyst notes are a separate region. The worker publishes an empty analyst
section. There is no UI to write notes in this build (**known limitation**).

## Related pages

- [Policy profiles](policy-profiles.md)
- [Interpret evidence](interpret-evidence.md)
- [Scoring and coverage](scoring-and-coverage.md)
- [Advisory ML](advisory-ml.md)

## Implementation anchors

- `src/securemail/domain/findings/finding.py`
- `src/securemail/domain/policies/rule_engine.py`
- `src/securemail/domain/policies/tls/forward_secrecy.py`

## Test evidence

- `tests/test_scoring_fixtures.py`
- `tests/unit/test_dedup.py`
- Fixture `tests/fixtures/tls13_psk_only_resumption/`
