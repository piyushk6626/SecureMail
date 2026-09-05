---
status: current
audience: architect
authoritative_for: payload-driven SMTP/IMAP/POP3 identification and independent port_hint
last_verified: 2026-09-06
---

# Protocol identification

Identification is **payload-driven**. Well-known ports are a hint, never
proof. Ambiguous banners resolve to `indeterminate`, not a guessed protocol.
A nonstandard-port fixture **must** show `port_hint=none` and
`payload_evidence` equal to the real protocol.

Normalizer: `normalize_sessions`. Model: `EmailSession`.

IMAP command-level depth uses bounded TShark, not Spicy. That choice is
[ADR 0001](../decisions/0001-imap-pop3-corroboration.md).

## Inputs

| Source | Used for |
|---|---|
| `Flow` | UID, endpoints, `port_hint` inputs |
| `sm_email.log` | Zeek confirming events, ambiguous banners, redacted commands |
| `ssl.log` | `ssl_history` letter `C`, selected ALPN `next_protocol` |
| Optional TShark frames | Mail command/status on well-known ports; ClientHello type `1` |

TShark runs only when `needs_tshark_corroboration` is true: any session with
smtp/imap/pop3 payload, any flow whose responder port is 465/993/995, or any
`ssl.log` row with a UID. The empty fixture skips TShark.

Display filter (current code, literal): `smtp or imap or pop or tls.handshake`.
See [STARTTLS](starttls-and-stls.md) for the historical ADR filter.

## Outputs

Independent fields on `EmailSession`:

| Field | Source |
|---|---|
| `port_hint` | Responder port, then originator port, against `{25,465,587}` smtp, `{143,993}` imap, `{110,995}` pop3; else `none` |
| `payload_evidence` | Zeek confirming events, optional TShark mail fields, optional selected ALPN |
| `protocol` | Same as payload when a single protocol is confirmed; `null` when indeterminate/conflicting |
| `evidence_state` | Identity visibility: `observed`, `indeterminate`, or `conflicting` |
| `identification_confidence` | `0.5` if Zeek and TShark disagree; otherwise `null` |
| `corroboration` | `zeek` or `zeek+tshark` |
| `events` | Bounded, redacted `ProtocolEvent` list (max 256) |

A standard-port fixture may have `port_hint == payload_evidence`; tests still
compare the two fields separately. Port equality is never treated as proof.

## Evidence states

| State | When identity uses it |
|---|---|
| `observed` | Exactly one protocol from Zeek ∪ TShark ∪ selected ALPN |
| `conflicting` | Zeek and TShark produced different protocol sets, or the combined set has more than one protocol |
| `indeterminate` | Ambiguous banner; TLS on 465/993/995 without selected ALPN; or no confirming events |
| `not_observable` | Not used as the session identity state. Explicit upgrade without evidence is `not_observable` on `explicit_upgrade`, not on identity |

Sessions with `payload_evidence=none` and no ambiguous banner are **dropped**,
unless the flow is an implicit-TLS candidate (responder 465/993/995 with SSL
evidence). Those become ALPN-identified or `indeterminate` sessions.

See [evidence states](../reference/evidence-states.md) and
[implicit TLS](implicit-tls.md).

## Precedence rules

### `port_hint`

`port_hint_for_flow` inspects responder port first, then originator:

1. `{25, 465, 587}` → `smtp`
2. `{143, 993}` → `imap`
3. `{110, 995}` → `pop3`
4. else `none`

This never writes `protocol` or `payload_evidence`.

### `_resolve_identity`

1. If both Zeek and TShark produced protocols and the sets differ →
   `protocol=null`, `payload_evidence=indeterminate`,
   `evidence_state=conflicting`, `identification_confidence=0.5`.
2. If the combined set (Zeek ∪ TShark ∪ selected ALPN) has more than one
   protocol → conflicting, confidence `null`.
3. If exactly one protocol → `observed`, that protocol, confidence `null`.
4. Else if an ambiguous banner was seen → `indeterminate`.
5. Else payload `none` (session dropped unless implicit-TLS candidate).

Selected ALPN `smtp` / `imap` / `pop3` from Zeek `ssl.log` `next_protocol`
counts toward identity. Offered-but-unselected ALPN is ignored.

### Zeek confirming events

Confirming event kinds (count toward identity): `request`, `reply`,
`capability`, `starttls`, `confirmation`, `unexpected`.

**SMTP:** `smtp_request` / `smtp_reply` / `smtp_starttls` — sufficient for
identity and for the STARTTLS command alphabet.

**POP3:** analyzer registered on 110/tcp and enabled by DPD off-port.
`pop3_request` / `pop3_reply` / `pop3_starttls`. CAPA body tokens (including
`STLS`) come from `pop3_data` only while CAPA is in progress.

**IMAP:** Zeek does not emit tagged commands. Identity uses
`imap_capabilities`, `imap_starttls`, and `analyzer_confirmation_info`
(`confirmation` events). Command-level STARTTLS evidence comes from TShark.

**Ambiguous banner:** DPD `sm_greeting_line` matches a printable responder
line without enabling a mail analyzer. If the UID is never confirmed, Zeek
writes `ambiguous_banner` / `protocol=unknown`. Python sets
`payload_evidence=indeterminate`, `protocol=null`. Fixture
`email_ambiguous_banner` uses port 25 so `port_hint=smtp` while payload stays
indeterminate.

### TShark mail fields

Frames join to flows by 5-tuple (IPv4/IPv6 + TCP ports). Exactly one matching
flow is required; ambiguous 5-tuples are dropped.

Protocol from TShark:

- IMAP: `imap.request.command` or `imap.response.status`
- POP: `pop.request.command` or `pop.response.indicator`
- SMTP: `smtp.req.command` or `smtp.response.code`

Events merge onto Zeek events on the same UID within **2.0 seconds** when
direction and command/status are compatible. TShark can add `frame_number`
and IMAP `tag` onto the Zeek event. Unmatched TShark events are appended.

TShark mail dissectors bind well-known ports. Off-port identity remains Zeek
DPD; those sessions stay `corroboration=zeek`.

## Uncertainty behavior

- Ambiguous banners are `indeterminate`, never a guessed smtp/imap/pop3.
- Zeek vs TShark disagreement is `conflicting` at confidence `0.5`, not a
  majority vote.
- TLS on 465/993/995 without selected ALPN is `indeterminate` identity, not
  smtp/imap/pop3 from the port.
- Implicit-TLS ALPN can identify a session even when the port is not
  465/993/995 (ALPN is payload evidence). See [implicit TLS](implicit-tls.md).
- Policy service roles require payload-confirmed protocol **and** a matching
  well-known port. Ambiguous or nonstandard SMTP stays `unclassified` so
  relay vs submission is never guessed from a port alone.

## Security bounds

Treat every banner, command, and argument as hostile.

| Bound | Value |
|---|---|
| Zeek rows / TShark frames | 10 000 each |
| Events per session | 256 |
| UID / host | 64 / 253 characters |
| Command / IMAP tag | 32 characters |
| Event text | 128 characters (Zeek also caps at 128) |
| Merge window | 2.0 seconds |

Secret commands have arguments and text replaced with `<redacted>`:

`AUTH`, `LOGIN`, `USER`, `PASS`, `APOP`, `AUTHENTICATE`, `AUTH_ANSWER`,
`**`, `MAIL`, `RCPT`.

TShark allowlist excludes secrets and full lines: no `imap.line`,
usernames, passwords, `smtp.req.parameter`, `pop.request.parameter`,
certificate bytes, or key-exchange material. DPD matching payload bytes are
not logged.

Analyzer argv is a fixed `list[str]`; never a shell string. Isolation flags
belong in [analyzer boundary](../architecture/analyzer-boundary.md).

## Fixture examples

| Fixture | `protocol` | `port_hint` | `payload_evidence` |
|---|---|---|---|
| `tcp_smtp_clean_baseline` (25) | smtp | smtp | smtp |
| `smtp_submission_port` (587) | smtp | smtp | smtp |
| `imap_standard_port` (143) | imap | imap | imap |
| `pop3_standard_port` (110) | pop3 | pop3 | pop3 |
| `smtp_nonstandard_port` | smtp | none | smtp |
| `imap_nonstandard_port` | imap | none | imap |
| `pop3_nonstandard_port` | pop3 | none | pop3 |
| `email_ambiguous_banner` | null | smtp | indeterminate |
| `smtp_public_corpus` / `imap_public_corpus` | matching | matching | matching |

Proof:

```bash
uv run securemail analyze tests/fixtures/pop3_nonstandard_port/capture.pcapng
```

## Limitations

- **Implemented:** payload identity independent of `port_hint`; DPD off-port
  SMTP/IMAP/POP3; ambiguous banner as indeterminate.
- **Known limitation:** TShark does not corroborate off well-known ports, so
  IMAP tagged commands on nonstandard ports are Zeek-only (no tags).
- **Known limitation:** no HTTP or other protocols.
- **Unsupported:** treating 465/993/995 without ALPN as smtp/imap/pop3.
- **Deferred:** Spicy IMAP analyzer. Revisit only if allowlisted TShark
  fields cannot express a later fixture.

## Related pages

- [TCP reconstruction](tcp-reconstruction.md)
- [STARTTLS and STLS](starttls-and-stls.md)
- [Implicit TLS](implicit-tls.md)
- [Evidence states](../reference/evidence-states.md)
- [ADR 0001 IMAP/POP3 corroboration](../decisions/0001-imap-pop3-corroboration.md)

## Implementation anchors

- `src/securemail/application/normalize_sessions.py`
- `src/securemail/domain/evidence/session.py`
- `zeek/scripts/securemail-email.zeek`
- `zeek/signatures/email-dpd.sig`
- `src/securemail/adapters/analyzers/tshark_runner.py`

## Test evidence

- `tests/test_protocol_fixtures.py`
- `tests/unit/test_normalize_sessions.py`
- `tests/unit/test_analyzer_argv.py`
