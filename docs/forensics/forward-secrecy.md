---
status: current
audience: architect
authoritative_for: version-aware forward secrecy assessment from handshake facts
last_verified: 2026-09-06
---

# Forward secrecy

Forward secrecy is a **derived assessment**, not a handshake field and not a
finding by itself. `assess_forward_secrecy` classifies a `TlsHandshake`.
YAML rules consume `derived.forward_secrecy.outcome` and emit
`TLS_FORWARD_SECRECY_ABSENT` or `TLS_FORWARD_SECRECY_INDETERMINATE` when
warranted. Present outcomes are passing `policy_checks`, not findings.

Never claim ephemeral-key reuse or session-ticket rotation from one PCAP.

## Inputs

| Input | Source |
|---|---|
| `handshake.version.selected` / `evidence_state` | [TLS handshakes](tls-handshakes.md) |
| `handshake.key_exchange.mechanism` / `evidence_state` | Same |
| `handshake.evidence_state` | Handshake-level completeness |
| `handshake.resumed` | Cited in PSK-only reasons |

TLS 1.3 KX must already have been classified from `key_share` / groups /
PSK modes, never from the AEAD cipher name.

## Outputs

`ForwardSecrecyAssessment`:

| Field | Values |
|---|---|
| `outcome` | `present`, `absent`, `indeterminate` |
| `evidence_state` | Copied from usable KX, or `indeterminate` |
| `reason_code` | Machine-readable why |
| `source_fields` | Paths the classifier used |

YAML:

- `TLS_FORWARD_SECRECY_ABSENT` — where outcome is `absent`; assertion is
  `present` (fail → negative finding)
- `TLS_FORWARD_SECRECY_INDETERMINATE` — where outcome is `indeterminate`;
  `fail_outcome: indeterminate`

## Evidence states

Usable KX/version states: `observed`, `verified`, `inferred`.

Handshake `incomplete` or `conflicting` → FS `indeterminate`
(`handshake_incomplete`). Unusable version → `version_unusable`. KX
`incomplete` / `conflicting` / `not_observable` → `key_exchange_unusable`.
Missing mechanism → `key_exchange_missing`.

`not_observable` KX (no mechanism visible) is indeterminate FS, not
“forward secrecy does not apply, therefore fine.”

PSK-only TLS 1.3 is designed-indeterminate: a single capture cannot prove
that the PSK was established with ephemeral agreement.

See [evidence states](../reference/evidence-states.md).

## Precedence rules

Version-aware table after the unusable-state guards:

| Version | Mechanism | Outcome | Reason |
|---|---|---|---|
| TLS 1.2 / 1.1 / 1.0 / SSL 3 | `ECDHE` or `DHE` | `present` | `tls12_ephemeral` |
| TLS 1.2 / 1.1 / 1.0 / SSL 3 | `RSA`, `DH`, or `ECDH` | `absent` | `static_key_exchange` |
| TLS 1.3 | `ECDHE`, `DHE`, `(EC)DHE`, `PSK-(EC)DHE` | `present` | `tls13_ephemeral` |
| TLS 1.3 | `PSK` | `indeterminate` | `tls13_psk_only` |
| TLS 1.3 | other | `indeterminate` | `tls13_unknown_mechanism` |
| TLS 1.2 family | other / KX `indeterminate` | `indeterminate` | `tls12_unknown_mechanism` or `key_exchange_indeterminate` |

TLS 1.2 `ECDHE`/`DHE` present includes DHE as ephemeral. Static `DH` and
`ECDH` are **absent** (fixed parameters), distinct from ephemeral `DHE` /
`ECDHE`.

TLS 1.3 `PSK-(EC)DHE` is present because a key_share was selected on the
resumption. `PSK` without key_share is not treated as present.

## Uncertainty behavior

- Incomplete handshake (truncated ClientHello) → indeterminate, not absent.
- Do not infer that an ECDHE session reused an ephemeral across connections.
- Do not infer ticket age, 0-RTT replay, or PSK binder strength beyond the
  observed mechanism.
- Present FS is not emitted as a finding; coverage still records `pass`.

## Security bounds

The function is pure and bounded by the already-normalized handshake. It
does not parse packets, does not touch ticket bytes, and does not log
key-share material (TShark already excludes
`tls.handshake.extensions_key_share_key_exchange`).

## Fixture examples

| Case | FS outcome |
|---|---|
| `tls12_ecdhe` | `present` (ECDHE) |
| `tls12_static_rsa` | `absent` |
| `tls12_static_ecdh` | `absent` |
| `tls12_static_dh` | `absent` + policy `TLS12_STATIC_DH_NEGOTIATED` |
| `tls13_full_handshake` | `present` from (EC)DHE key_share |
| `tls13_psk_only_resumption` | `indeterminate` (`PSK`); Step 7 CLI proof |
| `tls_truncated_client_hello` | `indeterminate` (`handshake_incomplete`) |

Proof (PSK-only + IETF pack):

```bash
uv run securemail analyze tests/fixtures/tls13_psk_only_resumption/capture.pcapng \
  --policy-profile ietf_current
```

## Limitations

- **Implemented:** version-aware present/absent/indeterminate table consumed
  by all three built-in packs.
- **Unsupported:** claiming DHE reuse, ticket rotation, or 0-RTT properties
  from one PCAP.
- **Deferred:** multi-capture correlation of ticket lifetime.

## Related pages

- [TLS handshakes](tls-handshakes.md)
- [Policy evaluation](policy-evaluation.md)
- [Policy packs](../reference/policy-packs.md)
- [Finding deduplication](finding-deduplication.md)

## Implementation anchors

- `src/securemail/domain/policies/tls/forward_secrecy.py`
- `src/securemail/domain/policies/tls/key_exchange.py`
- `src/securemail/domain/policies/rules/ietf_current.yaml` (`TLS_FORWARD_SECRECY_*`)

## Test evidence

- `tests/unit/test_forward_secrecy.py`
- `tests/test_policy_fixtures.py` (`tls13_psk_only_resumption`, `tls12_static_dh`)
