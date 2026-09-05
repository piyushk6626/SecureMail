---
status: current
audience: architect
authoritative_for: standards cited by live policy packs and identity matching
last_verified: 2026-09-06
---

# Standards

SecureMail cites standards in YAML `standards:` lists and in domain code
comments. This page lists the documents the **live** packs and validators
actually use. It is not a compliance certification.

## Transport and TLS

| Document | Used for |
|---|---|
| RFC 5246 | TLS 1.2 handshake facts |
| RFC 8446 | TLS 1.3; `supported_versions` over legacy record version; post-`ServerHello` encryption |
| RFC 7301 | ALPN (`smtp` / `imap` / `pop3`) as implicit-TLS correlation |
| RFC 5746 | Renegotiation is not assessed from one PCAP |
| RFC 7507 | Fallback SCSV is not a current rule |
| RFC 7568 | SSLv3 prohibited (`TLS_NEGOTIATED_SSL3`) |
| RFC 7525 / RFC 9325 | Historical SHOULD NOT language for TLS 1.0/1.1 and static RSA |
| RFC 8996 | TLS 1.0 / 1.1 MUST NOT (`TLS_NEGOTIATED_TLS10`, `TLS_NEGOTIATED_TLS11`) |
| IANA TLS Parameters snapshot | Cipher names/codes; not hardcoded Python literals |

## Mail

| Document | Used for |
|---|---|
| RFC 3207 | SMTP STARTTLS |
| RFC 2595 | IMAP STARTTLS / POP3 STLS; POP3 PASS without TLS |
| RFC 8314 / RFC 8997 | Submission and access cleartext deprecation; plaintext fallback |
| RFC 9051 | IMAP LOGIN without TLS |
| RFC 5321 | SMTP command alphabet (facts, not findings) |

## PKI and identity

| Document | Used for |
|---|---|
| RFC 5280 | Validity windows, path building at an explicit time |
| RFC 9525 | SAN matching; **no CN fallback** |
| RFC 4514 | Subject/issuer string encoding |
| RFC 6960 / RFC 5280 CRL | Revocation; always `unknown` without imported OCSP/CRL |

## NIST (federal pack)

| Document | Used for |
|---|---|
| SP 800-52 | Approved TLS suite names (`NIST_TLS_SUITE_NOT_APPROVED`) |
| SP 800-57 / SP 800-131A | Effective strength table (RSA-2048 → 112-bit; P-256 → 128-bit) |
| FIPS 140 | Not used as a finding code. “Not FIPS-approved” ≠ cryptographically weak |

## Report integrity

| Document | Used for |
|---|---|
| RFC 8785 | Canonical JSON (JCS) for `report.json` |
| RFC 3339 | UTC timestamps with `Z` |

## Related pages

- [Policy packs](policy-packs.md)
- [Evidence states](evidence-states.md)
- [Chain and identity validation](../forensics/chain-and-identity-validation.md)

## Implementation anchors

- `src/securemail/domain/policies/rules/*.yaml`
- `src/securemail/domain/policies/pki/identity.py`
- `src/securemail/adapters/reference_data/iana_tls_parameters.py`

## Test evidence

- `tests/unit/test_identity.py`
- `tests/unit/test_canonical_json.py`
- YAML `tests:` blocks inside each pack
