---
status: current
audience: security
authoritative_for: bounds and sanitization of untrusted inputs
last_verified: 2026-09-06
---

# Untrusted input handling

Every capture, banner, certificate string, and report field is hostile.
Numeric caps are owned by [limits](../reference/limits.md); this page names
the handling.

## PCAP / PCAPNG

- Extension must match magic (`PCAP_MAGICS` / `PCAPNG_MAGIC`).
- CLI Typer requires an existing readable file. API streams to quarantine
  with a byte cap (default 64 MiB).
- Original file is hashed before analyzers. Working copies are analyzed.
- Competing TCP reconstructions are preserved when bytes do not support one
  deterministic stream (`conflicting`), never silently repaired.

## Analyzer output

- Combined analyzer output 50 MiB. Zeek rows / TShark frames 10 000 each.
- Events per session 256. UID/fingerprint 64 chars. Hostnames 253. Commands
  and tags 32. Event text 128.
- TShark uses a **literal** display filter and allowlisted `-e` fields. Full
  lines and password fields are excluded. Current filter:
  `smtp or imap or pop or tls.handshake` — see [decision 0001](../decisions/0001-imap-pop3-corroboration.md).

## Certificates

- 64 KiB DER, 16 constructed ASN.1 levels, 256 certificates per run, chain
  depth 16. Oversized or over-nested input is `syntax_valid: false` without a
  large `cryptography` allocation.
- Content-addressed store refuses empty bytes and path escape.

## JSON and YAML

- Score CLI and report CLI cap input at 8 MiB.
- Policy packs: 256 KiB, 128 rules, 16 predicates. Loaded from the in-repo
  path only — no user-supplied pack path.
- Catalog index 1 MiB. Canonical report JSON 8 MiB. HTML 16 MiB. PDF 32 MiB.

## Identifiers and paths

Case id / run id: `^[A-Za-z0-9][A-Za-z0-9._-]*$`, 1–160 characters.
Original filename 255 characters, sanitized. Catalog and job store reject
symlinked roots and traversal.

## Redaction

Secret commands (`AUTH`, `LOGIN`, `USER`, `PASS`, `APOP`, `AUTHENTICATE`,
`AUTH_ANSWER`, `**`, `MAIL`, `RCPT`) have argument/text replaced with
`<redacted>`. Do not log packet payloads, credentials, or private/session
keys.

## Related pages

- [Limits](../reference/limits.md)
- [Data handling and privacy](data-handling-and-privacy.md)
- [Threat model](threat-model.md)

## Implementation anchors

- `src/securemail/application/capture_intake.py`
- `src/securemail/application/run_analysis.py`
- `src/securemail/adapters/analyzers/tshark_runner.py`
- `src/securemail/application/normalize_certificates.py`

## Test evidence

- `tests/unit/test_capture_intake.py`
- `tests/unit/test_parse_certificate.py`
- `tests/unit/test_analyzer_argv.py`
- `tests/test_analysis_api.py`
