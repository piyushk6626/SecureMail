# Step 2 decision: IMAP/POP3 event depth for Step 3 STARTTLS state machines

Date: 2026-09-04
Status: accepted
Step: 2 (protocol identification)

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
| POP3 | `pop3_request`, `pop3_reply`, `pop3_starttls` (after enablement) | CAPA/QUIT request lines and `+OK`/`-ERR` replies | Sufficient for command-level STLS. CAPA advertisement is visible as a `CAPA` request plus the server reply. |
| IMAP | `imap_capabilities`, `imap_starttls`, plus `analyzer_confirmation_info` | Only `confirmation` and `capability` (capability token list). No tagged `CAPABILITY`/`STARTTLS`/`LOGOUT` commands, no OK/NO/BAD lines | Insufficient. Step 3 needs the CAPABILITY command, the STARTTLS command, tagged completion, and post-upgrade refresh — none of which Zeek emits as lines. |

Step 2 identification itself does **not** need IMAP command lines:
`imap_capabilities` / analyzer confirmation plus DPD correctly identified IMAP
on TCP/143 and on TCP/1143. The gap is forward-looking for Step 3.

## Decision

- **SMTP:** stay on Zeek built-in events. No second pass.
- **POP3:** stay on Zeek built-in events for identification and for the Step 3
  command alphabet. TShark is still run as corroboration when a POP3 session is
  present because the build plan names a single bounded filter `imap or pop`.
- **IMAP:** escalate to a **bounded TShark second pass**, not Spicy.

Spicy is deferred: TShark already dissects IMAP command verbs and tagged
status through allowlisted fields, which is enough to populate
`EmailSession.events` for Step 3 without a new analyzer binary.

## TShark contract (fixed argv, allowlisted fields only)

Display filter (literal, not caller-supplied): `imap or pop`

Allowlisted `-e` fields:

- `frame.number`, `frame.time_epoch`
- `ip.src`, `ip.dst`, `ipv6.src`, `ipv6.dst`
- `tcp.srcport`, `tcp.dstport`
- `imap.request.command`, `imap.response.status`, `imap.tag`, `imap.isrequest`
- `pop.request.command`, `pop.response.indicator`

Explicitly excluded (secrets / full lines): `imap.line`,
`imap.request.username`, `imap.request.password`, `pop.request.parameter`,
`pop.request.data`, `pop.response.data`.

The pass runs only after Zeek has already identified IMAP or POP3 on a
session (`needs_imap_pop_corroboration`). SMTP-only and non-mail captures do
not start TShark. Zeek remains primary; TShark frames are joined by 5-tuple.
Disagreement is recorded as `evidence_state=conflicting` with
`identification_confidence=0.5`.

TShark's IMAP/POP dissectors bind to well-known ports by default. Nonstandard
port identification therefore stays on Zeek DPD (proven by
`imap_nonstandard_port` and `pop3_nonstandard_port`). TShark corroboration
adds command/status lines on 143/110 and the public IMAP corpus.

## Consequences

- Step 3 IMAP state machines consume `EmailSession.events` (Zeek capabilities
  plus TShark command/status), not a new Zeek IMAP log.
- A Spicy IMAP analyzer is not introduced in this step. Revisit only if the
  pinned TShark fields cannot express a later fixture (for example, capability
  stripping that needs the raw untagged `* CAPABILITY` line beyond
  `imap.response.status`).
