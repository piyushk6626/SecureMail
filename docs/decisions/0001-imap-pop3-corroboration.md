---
status: current
audience: architect
authoritative_for: IMAP/POP3 TShark corroboration vs Spicy
last_verified: 2026-09-06
---

# Step 2 decision: IMAP/POP3 event depth for Step 3 STARTTLS state machines

> **As-built note (2026-09-06):** the live TShark display filter is
> `smtp or imap or pop or tls.handshake` in
> [`tshark_runner.py`](../../src/securemail/adapters/analyzers/tshark_runner.py)
> (`TSHARK_DISPLAY_FILTER`). That is **broader** than the filter recorded
> below (`tls.handshake.type == 1`). Handshake **type** is still requested as
> an allowlisted `-e` field; the display filter no longer restricts to
> ClientHello (`type == 1`) only. Do not “correct” the historical decision
> text; treat this note as the live contract.

Date: 2026-09-04
Status: accepted
Step: 2 (protocol identification); amended for Step 3 (2026-09-04)

## Question

Are Zeek 8.0.10's built-in IMAP and POP3 events sufficient for Step 3's
STARTTLS/STLS state machines (`advertised`, `requested`, `accepted`,
`tls_established`, `plaintext_fallback`, `violation`), or must SecureMail
escalate per protocol to a small Spicy analyzer or a bounded TShark second
pass?

## Evidence collected on Step 2 fixtures

Analyzers were exercised against lab, Scapy, and public-corpus captures with
POP3 enabled (`Analyzer::register_for_ports` plus DPD) and SMTP/IMAP/POP3
payload signatures loaded. Observed `sm_email.log` event kinds:

| Protocol | Built-in events used | Observed on fixtures | Step 3 alphabet coverage |
|---|---|---|---|
| SMTP | `smtp_request`, `smtp_reply`, `smtp_starttls` | EHLO/MAIL/RCPT/DATA/QUIT command/response lines with reply codes | Sufficient. STARTTLS request/response will appear as the same command/reply events. |
| POP3 | `pop3_request`, `pop3_reply`, `pop3_starttls` (after enablement) | CAPA/QUIT request lines and `+OK`/`-ERR` replies | Command-level STLS is sufficient. Multi-line CAPA body tokens (`STLS`) are **not** on the first `pop3_reply` line; Step 3 emits them from `pop3_data` only while a CAPA response is active. |
| IMAP | `imap_capabilities`, `imap_starttls`, plus `analyzer_confirmation_info` | Only `confirmation` and `capability` (capability token list). No tagged `CAPABILITY`/`STARTTLS`/`LOGOUT` commands, no OK/NO/BAD lines | Insufficient. Step 3 needs the CAPABILITY command, the STARTTLS command, tagged completion, and post-upgrade refresh — none of which Zeek emits as lines. |

Step 2 identification itself does **not** need IMAP command lines:
`imap_capabilities` / analyzer confirmation plus DPD correctly identified IMAP
on TCP/143 and on TCP/1143. The gap is forward-looking for Step 3.

## Decision

- **SMTP:** Zeek built-in events remain primary. Step 3 adds a bounded TShark
  pass for SMTP command/status and TLS ClientHello **frame numbers**, not for
  protocol identity.
- **POP3:** Zeek built-in events remain primary for the command alphabet.
  `pop3_data` is consumed only during an in-progress CAPA response so `STLS`
  advertisement is observable. `pop3_unexpected` is logged as a sanitized
  `unexpected` event (`msg` only; never `detail`). TShark still corroborates
  when a POP3 session is present.
- **IMAP:** escalate to a **bounded TShark second pass**, not Spicy.

Spicy is deferred: TShark already dissects IMAP command verbs and tagged
status through allowlisted fields, which is enough to populate
`EmailSession.events` for Step 3 without a new analyzer binary.

## TShark contract (fixed argv, allowlisted fields only)

Display filter (literal, not caller-supplied):
`smtp or imap or pop or tls.handshake.type == 1`

Allowlisted `-e` fields:

- `frame.number`, `frame.time_epoch`
- `ip.src`, `ip.dst`, `ipv6.src`, `ipv6.dst`
- `tcp.srcport`, `tcp.dstport`
- `imap.request.command`, `imap.response.status`, `imap.tag`, `imap.isrequest`
- `pop.request.command`, `pop.response.indicator`
- `smtp.req.command`, `smtp.response.code`
- `tls.handshake.type`

Explicitly excluded (secrets / full lines): `imap.line`,
`imap.request.username`, `imap.request.password`, `pop.request.parameter`,
`pop.request.data`, `pop.response.data`, `smtp.req.parameter`,
`smtp.auth.password`, `smtp.auth.username`.

The pass runs after Zeek has identified SMTP/IMAP/POP3 **or** when a flow on
an implicit-TLS port (465/993/995) has TLS evidence
(`needs_tshark_corroboration`). Empty and non-mail captures do not start
TShark. Zeek remains primary; TShark frames are joined by 5-tuple and merged
by timestamp. Disagreement on protocol identity is recorded as
`evidence_state=conflicting` with `identification_confidence=0.5`.

TShark's IMAP/POP/SMTP dissectors bind to well-known ports by default.
Nonstandard port identification therefore stays on Zeek DPD (proven by
`imap_nonstandard_port` and `pop3_nonstandard_port`). TShark corroboration
adds command/status and ClientHello frame numbers on well-known ports.

## Implicit TLS (Step 3 amendment)

Positive correlation of implicit mail-over-TLS requires independently
decoded protocol evidence. Selected ALPN (`next_protocol` of `smtp`, `imap`,
or `pop3`) is accepted. Offered-but-unselected ALPN and TLS on 465/993/995
without ALPN remain `indeterminate`. The well-known port is `port_hint`
only.

## Consequences

- Step 3 IMAP state machines consume `EmailSession.events` (Zeek capabilities
  plus TShark command/status), not a new Zeek IMAP log.
- POP3 `advertised` for STLS is now observable from bounded CAPA tokens.
- Frame references on upgrade assessments come from the TShark pass.
- `tls_established` is gated on an observed TLS ClientHello (`ssl_history`
  contains `C` and/or `tls.handshake.type == 1`), never on the STARTTLS
  command alone.
- A Spicy IMAP analyzer is not introduced in this step. Revisit only if the
  pinned TShark fields cannot express a later fixture (for example, capability
  stripping that needs the raw untagged `* CAPABILITY` line beyond
  `imap.response.status`).
