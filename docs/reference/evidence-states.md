---
status: current
audience: user
authoritative_for: EvidenceState vocabulary and missing-evidence rules
last_verified: 2026-09-06
---

# Evidence states

Every applicable evidence field uses exactly these seven states, defined once
as `EvidenceState` in
[`src/securemail/domain/evidence/run.py`](../../src/securemail/domain/evidence/run.py).
Nothing else redefines the enum.

**Missing evidence is not a pass.** A test or UI that treats `not_observable`,
`incomplete`, or `indeterminate` as “no weakness detected” / “secure” is a bug.

| State | Meaning in this build |
|---|---|
| `observed` | Directly seen (complete TCP stream, confirmed protocol, terminal upgrade state with evidence, extracted DER facts). |
| `verified` | Reserved on evidence classifiers. Findings use it as `evaluation_state` for a confirmed **negative** rule. |
| `inferred` | Derived from a named grammar, not from a missing observation. TLS 1.2 key exchange from the IANA suite-name grammar; TLS 1.3 PSK-only when `key_share` is absent. |
| `incomplete` | Reconstruction missing bytes or boundaries; truncated ClientHello with no selected version; `CertificateVerify` letter `y` present but the algorithm is not decoded. |
| `conflicting` | Overlapping retransmission conflict, or Zeek vs TShark protocol disagreement. |
| `not_observable` | The fact cannot be seen from this capture given protocol design or absence of the relevant attempt. Includes TLS 1.3 certificates after `ServerHello` (encrypted; no history letter `x`), no STARTTLS/STLS attempt, and implicit-TLS correlation when the flow is not on 465/993/995 **and** no selected ALPN. |
| `indeterminate` | Ambiguous banner; TLS on a mail port without selected ALPN; unresolved identity (missing SNI and missing `--expected-hostname`). |

## Scoring weights

`securemail.scoring/v1` maps `basis_state` to integer confidence points. The
table is in [scoring](../user-guide/scoring-and-coverage.md). `not_observable` contributes **0**
confidence points; it is still counted in coverage denominators, never folded
into `passed_count`.

## Classifier assignment (today)

| Area | Typical states |
|---|---|
| Flow reconstruction | `observed` (complete), `incomplete`, `conflicting` |
| Protocol identity | `observed`, `indeterminate`, `conflicting` |
| Explicit upgrade | `observed` when a machine state is set; otherwise `not_observable` |
| Implicit TLS | `observed` (selected ALPN), `indeterminate` (465/993/995 without ALPN), `not_observable` otherwise |
| Handshake | `observed` / `incomplete` / `conflicting`; TLS 1.3 cert/`CertificateVerify` often `not_observable` |
| Certificate facts | `observed` or `incomplete` (truncated DER); no record is emitted when TLS 1.3 hides the chain |
| Policy check coverage | `pass` / `fail` / `unknown` / `not_observable` (coverage vocabulary, not the evidence enum) |

`verified` is unused by flow, session, handshake, and certificate classifiers.

## Related pages

- [Evidence schema](evidence-schema.md)
- [Decision 0004](../decisions/0004-evidence-state-semantics.md)
- [Interpret evidence](../user-guide/interpret-evidence.md)

## Implementation anchors

- `src/securemail/domain/evidence/run.py`
- `src/securemail/domain/findings/scoring.py`

## Test evidence

- `tests/unit/test_evidence_state.py`
- Fixture harness asserts the state field itself, not a derived “secure” boolean
