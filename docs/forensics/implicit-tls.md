---
status: current
audience: architect
authoritative_for: implicit TLS correlation via selected ALPN never via port number
last_verified: 2026-09-06
---

# Implicit TLS

Implicit mail-over-TLS (SMTPS / IMAPS / POP3S) is correlated from
**decoded protocol evidence**, not from the well-known port. Ports 465, 993,
and 995 are `port_hint` only.

Pure function: `correlate_implicit_tls` in
`domain/policies/starttls/implicit_tls.py`. `normalize_sessions` always
attaches an `ImplicitTls` object from the flow’s responder port and SSL /
ALPN facts.

## Inputs

| Input | Source |
|---|---|
| `responder_port` | `Flow.resp.port` |
| `tls_on_connection` | An `ssl.log` row for the UID, or TShark ClientHello frames |
| `negotiated_alpn` | Zeek `ssl.log` `next_protocol` only (selected ALPN) |
| `alpn_frames` | ClientHello frame numbers when ALPN maps to smtp/imap/pop3 |

Offered-but-unselected ALPN is ignored. `protocol_from_alpn` accepts only
the identifiers `smtp`, `imap`, and `pop3` (case-insensitive).

## Outputs

`ImplicitTls` on every normalized session:

| Field | Meaning |
|---|---|
| `correlated_protocol` | Set only from selected ALPN `smtp` / `imap` / `pop3` |
| `evidence_state` | `observed`, `indeterminate`, or `not_observable` |
| `source` | `alpn`, `none`, or `null` |
| `evidence_frames` | ClientHello frames when ALPN correlation succeeded |

Port number never sets `correlated_protocol`.

When identity had no confirming mail events, implicit-TLS **session
creation** still keeps a UID that is on 465/993/995 with SSL evidence.
Selected ALPN then fills `protocol` / `payload_evidence`; otherwise identity
stays `indeterminate`. See [protocol identification](protocol-identification.md).

## Evidence states

`correlate_implicit_tls` first-match:

| Condition | `correlated_protocol` | `evidence_state` | `source` |
|---|---|---|---|
| TLS on the connection **and** selected ALPN in `{smtp, imap, pop3}` | that protocol | `observed` | `alpn` |
| Responder port in {465, 993, 995} and TLS, no selected ALPN | `null` | `indeterminate` | `none` |
| Responder port in that set, no TLS | `null` | `indeterminate` | `none` |
| Other ports, no selected mail ALPN | `null` | `not_observable` | `null` |

The first row is **port-independent**. Selected mail ALPN plus TLS returns
`observed` even if the port is **not** 465/993/995 (for example submission
587 or a nonstandard port that negotiated ALPN).

`not_observable` means implicit-TLS correlation **cannot be observed**: the
capture is not on the classic implicit-TLS ports and no selected mail ALPN
is present. It is not “implicit TLS does not apply, therefore secure.”
Explicit STARTTLS on 143/25/110 typically lands here for the implicit
object while the explicit upgrade object carries the STARTTLS state.

See [evidence states](../reference/evidence-states.md).

## Precedence rules

Order inside `correlate_implicit_tls`:

1. If `protocol_from_alpn(negotiated_alpn)` is smtp/imap/pop3 **and**
   `tls_on_connection` → `observed` / `source=alpn`. Stop.
2. Else if responder port ∈ {465, 993, 995} and TLS → `indeterminate` /
   `source=none`.
3. Else if responder port ∈ {465, 993, 995} (no TLS) → `indeterminate` /
   `source=none`.
4. Else → `not_observable` / `source=null`.

Identity resolution may still use the same selected ALPN as payload
evidence on any port. Implicit TLS and `payload_evidence` stay separate
fields; tests compare them independently.

TShark still runs when a flow’s responder port is 465/993/995 so ClientHello
frame numbers can be cited when ALPN correlation succeeds
(`needs_tshark_corroboration`).

## Uncertainty behavior

- TLS on 993 without ALPN (`tls_mail_port_no_alpn`): `protocol=null`,
  `payload_evidence=indeterminate`, `implicit_tls.evidence_state=indeterminate`.
  The port is **not** treated as IMAP.
- Empty `next_protocol` is treated like no ALPN (indeterminate on 465/993/995).
- Explicit STARTTLS sessions usually have `implicit_tls` `not_observable`
  (port 25/143/110, no mail ALPN).
- Policy must not infer SMTPS/IMAPS/POP3S from port 465/993/995 alone.

Lab implicit-TLS fixtures negotiate ALPN and assert `payload_evidence`
matches `correlated_protocol`. There is no committed PCAP that proves
ALPN-on-non-465/993/995; that branch is covered by the function’s first
rule and by `test_smtp_alpn_on_submission_port` (port 465, which is in the
implicit set). The first-rule port independence is visible in source:
ALPN is checked **before** `IMPLICIT_TLS_PORTS`.

## Security bounds

| Bound | Value |
|---|---|
| ALPN token | 32 characters when copied from `ssl.log` |
| Frame numbers | Positive integers, unique, sorted |
| Port set | Frozen `{465, 993, 995}` — not caller-extensible at runtime |

No packet payload is consulted beyond Zeek’s already-decoded
`next_protocol`. TShark is not the ALPN source.

## Fixture examples

| Fixture | Result |
|---|---|
| `smtp_implicit_tls` | ALPN smtp, `implicit_tls.observed`, `correlated_protocol=smtp` |
| `imap_implicit_tls` | ALPN imap |
| `pop3_implicit_tls` | ALPN pop3 |
| `tls_mail_port_no_alpn` | TLS on 993, no ALPN → identity and implicit TLS `indeterminate` |
| `smtp_starttls_success` | Explicit `tls_established`; implicit typically `not_observable` |

Proof:

```bash
uv run securemail analyze tests/fixtures/tls_mail_port_no_alpn/capture.pcapng
```

## Limitations

- **Implemented:** selected-ALPN correlation; port-only stays indeterminate
  on 465/993/995; other ports without ALPN are `not_observable`.
- **Known limitation:** no PCAP fixture with mail ALPN on a port outside
  {465, 993, 995}. Unit tests cover 993/465/995/143.
- **Unsupported:** treating offered-but-unselected ALPN as correlation.
- **Unsupported:** inferring protocol from port 465/993/995.
- **Deferred:** other ALPN identifiers (for example `smtps`) are not mapped.

## Related pages

- [Protocol identification](protocol-identification.md)
- [STARTTLS and STLS](starttls-and-stls.md)
- [TLS handshakes](tls-handshakes.md)
- [Evidence states](../reference/evidence-states.md)

## Implementation anchors

- `src/securemail/domain/policies/starttls/implicit_tls.py`
- `src/securemail/application/normalize_sessions.py` (`_assess_session`, implicit candidates)

## Test evidence

- `tests/unit/test_implicit_tls.py`
- `tests/test_starttls_fixtures.py` (implicit TLS and `tls_mail_port_no_alpn`)
- `tests/fixtures/smtp_implicit_tls/`, `imap_implicit_tls/`, `pop3_implicit_tls/`
