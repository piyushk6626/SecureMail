# Protocol identification

Identification is **payload-driven**. Well-known ports are a hint, never proof.
Ambiguous banners resolve to `indeterminate`, not a guessed protocol.

Normalizer: [`normalize_sessions.py`](../src/securemail/application/normalize_sessions.py).
Model: [`EmailSession`](../src/securemail/domain/evidence/session.py).

## Independent fields

| Field | Source |
|---|---|
| `port_hint` | Responder port, then originator port, against `{25,465,587}` smtp, `{143,993}` imap, `{110,995}` pop3; else `none` |
| `payload_evidence` | Zeek confirming events, optional TShark mail fields, optional selected ALPN |
| `protocol` | Same as payload when a single protocol is confirmed; `null` when indeterminate/conflicting |
| `evidence_state` | `observed`, `indeterminate`, or `conflicting` |
| `identification_confidence` | `0.5` if Zeek and TShark disagree; otherwise `null` |
| `corroboration` | `zeek` or `zeek+tshark` |

A nonstandard-port fixture **must** show `port_hint=none` and
`payload_evidence` equal to the real protocol. A standard-port fixture may have
them equal; tests still compare the two fields separately.

## Zeek evidence

[`zeek/scripts/securemail-email.zeek`](../zeek/scripts/securemail-email.zeek)
plus DPD in [`zeek/signatures/email-dpd.sig`](../zeek/signatures/email-dpd.sig).

**Confirming event kinds** (count toward identity): `request`, `reply`,
`capability`, `starttls`, `confirmation`, `unexpected`.

**SMTP:** `smtp_request` / `smtp_reply` / `smtp_starttls` — sufficient for
identity and for Step 3’s command alphabet.

**POP3:** analyzer registered on 110/tcp and enabled by DPD off-port.
`pop3_request` / `pop3_reply` / `pop3_starttls`. CAPA body tokens (including
`STLS`) come from `pop3_data` only while CAPA is in progress.

**IMAP:** Zeek does not emit tagged commands. Identity uses
`imap_capabilities`, `imap_starttls`, and `analyzer_confirmation_info`
(`confirmation` events). Command-level STARTTLS evidence for Step 3 comes from
TShark (ADR).

**Ambiguous banner:** DPD `sm_greeting_line` matches a printable responder line
without enabling a mail analyzer. If the UID is never confirmed, Zeek writes
`ambiguous_banner` / `protocol=unknown`. Python sets
`payload_evidence=indeterminate`, `protocol=null`. The
`email_ambiguous_banner` fixture uses port 25 so `port_hint=smtp` while payload
stays indeterminate.

## TShark evidence

When the corroboration gate fires, frames are joined to flows by 5-tuple
(IPv4/IPv6 + TCP ports). Protocol from TShark:

- IMAP fields `imap.request.command` or `imap.response.status`
- POP fields `pop.request.command` or `pop.response.indicator`
- SMTP fields `smtp.req.command` or `smtp.response.code`

Events are merged into Zeek events on the same UID within **2.0 seconds** when
direction and command/status are compatible. TShark can add `frame_number` and
IMAP `tag` onto the Zeek event. Unmatched TShark events are appended.

TShark mail dissectors bind well-known ports. Off-port identity remains Zeek
DPD; those sessions stay `corroboration=zeek`.

## Identity resolution

`_resolve_identity` in the session normalizer:

1. If both Zeek and TShark produced protocols and the sets differ →
   `protocol=null`, `payload_evidence=indeterminate`,
   `evidence_state=conflicting`, `identification_confidence=0.5`.
2. If the combined set (Zeek ∪ TShark ∪ selected ALPN) has more than one
   protocol → conflicting, confidence `null`.
3. If exactly one protocol → `observed`, that protocol, confidence `null`.
4. Else if an ambiguous banner was seen → `indeterminate`.
5. Else payload `none` (session dropped unless implicit-TLS candidate).

**Implicit TLS without plaintext:** a flow on 465/993/995 with `ssl.log` and no
mail confirming events still becomes a session. Selected ALPN `smtp`/`imap`/`pop3`
fills protocol; otherwise `payload_evidence=indeterminate` (fixture
`tls_mail_port_no_alpn`).

## Standard vs nonstandard vs corpus

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

Public-corpus traces are regression only; they are not the sole proof of a
rule.

Proof command: `securemail analyze tests/fixtures/pop3_nonstandard_port/capture.pcapng`.

## Not in this build

No ALPN-based identification except the implicit-TLS path above. No HTTP or
other protocols. Port 465/993/995 without ALPN is **not** treated as
smtp/imap/pop3.
