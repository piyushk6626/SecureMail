---
status: current
audience: user
authoritative_for: evidence-state meaning for analysts reading EvidenceDocument
last_verified: 2026-09-06
---

# Interpret evidence

Every applicable evidence field carries an `EvidenceState`. The enum is defined
once in `domain/evidence/run.py`. Nothing else may invent a parallel
vocabulary.

```text
observed | verified | inferred | incomplete | conflicting | not_observable | indeterminate
```

**Never** treat `not_observable`, `incomplete`, or `indeterminate` as “secure,”
“no weakness detected,” or a coverage pass. Tests that do so are bugs in the
test. The dashboard and HTML/PDF keep those states visible as labels, not as
green checks.

`verified` is reserved. Current classifiers do not assign it on flow, session,
handshake, or certificate records. Negative findings use `evaluation_state`
`verified`; that is a finding field, not a claim that the packet evidence was
cryptographically verified.

## State meanings in this build

| State | Typical assignment |
|---|---|
| `observed` | Directly seen: complete TCP stream, confirmed protocol, terminal upgrade state with evidence, negotiated TLS version from `supported_versions` or legacy record. |
| `verified` | Unused by evidence classifiers. |
| `inferred` | TLS 1.2 key exchange taken from the IANA suite-name grammar; TLS 1.3 PSK-only when `key_share` is absent. |
| `incomplete` | Reconstruction missing bytes or boundaries; truncated ClientHello with no selected version. |
| `conflicting` | Overlapping retransmission conflict, or Zeek vs TShark protocol disagreement. |
| `not_observable` | The check does not apply or the bytes are designed-invisible (no upgrade attempt; implicit TLS not on 465/993/995; TLS 1.3 certificates after ServerHello without history letter `x`). |
| `indeterminate` | Ambiguous banner; TLS on a mail port without selected ALPN; unresolved identity. |

Coverage mapping when a rule cannot be asserted: `incomplete`, `conflicting`,
and `indeterminate` become policy-check `unknown`; `not_observable` becomes
`not_observable`. See [scoring and coverage](scoring-and-coverage.md).

## Record types

Read these as facts, not conclusions. Policy findings are a separate array.

### Capture preflight

From capinfos, before Zeek: packet count, time precision, snaplen, truncated
packet flag, duration, `capture_start_time`.
`truncated_packets_present` is capture-wide; the flow classifier receives it
on every flow in that run.

### Flows

TCP reconstruction quality is `complete`, `incomplete`, or `conflicting`.
Evidence state maps from quality. Non-TCP flows are `complete` unless the
capture has truncated packets. Competing reconstructions are preserved when
bytes do not support one deterministic stream. Gap counts are not invented
when inexact (`gap_bytes_exact=false`).

### Sessions

Protocol identity is payload-driven. `port_hint` is not proof.
`port_hint != payload_evidence` is an expected fixture assertion (for example
POP3 on a nonstandard port: `port_hint=none`, `payload_evidence=pop3`).

STARTTLS/STLS `explicit_upgrade.state`: `advertised`, `requested`,
`accepted`, `tls_established`, `plaintext_fallback`, `violation`, or `null`.
`downgrade_consistent` is its own field — capability exchange seen,
STARTTLS/STLS not advertised, but upgrade still requested and accepted. It is
not “STARTTLS missing” and not proof of an attacker.

Implicit TLS `correlated_protocol` is set only from **selected** ALPN
`smtp` / `imap` / `pop3`. Port 993 with TLS and no ALPN is `indeterminate`,
not IMAP.

Secret command arguments (`AUTH`, `LOGIN`, `USER`, `PASS`, and others) are
redacted to `<redacted>` in events. Event text is bounded.

### Handshakes

`supported_versions` wins over the legacy record-layer version. Selected
version is never inferred from ClientHello offers. Cipher names/codes come
from the checked-in IANA snapshot. TLS 1.3 key exchange comes from
`key_share` / groups / PSK modes — **never** from the cipher-suite name.
PSK-only resumption is `PSK`; PSK with a selected key_share is `PSK-(EC)DHE`.

TLS 1.3 visibility is `partial` unless both the server certificate and
`CertificateVerify` are actually observed. History letter `x` / `y` gate
those fields. Certificates are not fabricated from `x509.log`.

Certificate signature algorithm ≠ handshake `CertificateVerify` algorithm.
Keep them separate.

### Certificates

Top-level array linked by Zeek `uid` and `chain_index` (0 = leaf).
`valid_at_capture_time` and `valid_at_analysis_time` are independent.
Path validity and `identity_match` are independent. SAN matching is RFC 9525
with **no CN fallback**. Missing SNI and missing `--expected-hostname` make
`identity_match` `null`, not a pass. Revocation without imported OCSP/CRL is
always `unknown` in this build. Trust profile id is `offline_v1`.

TLS 1.3 UIDs without history letter `x` emit **no** certificate records.

## Hostile strings

Banners, subjects, and event text are untrusted. HTML, PDF, and the dashboard
render them as text. Control and bidirectional characters are shown as visible
`\uXXXX` sequences. Canonical JSON keeps the original bytes.

## Related pages

- [Interpret findings](interpret-findings.md)
- [Evidence limitations](evidence-limitations.md)
- [As-built evidence model](../reference/evidence-schema.md)
- [TCP reconstruction](../forensics/tcp-reconstruction.md)

## Implementation anchors

- `src/securemail/domain/evidence/run.py`
- `src/securemail/domain/evidence/flow.py`
- `src/securemail/domain/evidence/session.py`
- `src/securemail/domain/evidence/handshake.py`
- `src/securemail/domain/evidence/certificate.py`

## Test evidence

- `tests/unit/test_evidence_state.py`
- `tests/test_tcp_fixtures.py`
- `tests/test_protocol_fixtures.py`
- `tests/test_starttls_fixtures.py`
- `tests/test_tls_fixtures.py`
- `tests/test_certificate_fixtures.py`
- `tests/test_certificate_chain_fixtures.py`
