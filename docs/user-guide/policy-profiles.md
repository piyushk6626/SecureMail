---
status: current
audience: user
authoritative_for: built-in policy profile selection and evaluation clocks
last_verified: 2026-09-06
---

# Policy profiles

Analyze applies one versioned YAML pack. Packs live under
`src/securemail/domain/policies/rules/`. The CLI and upload API accept the
same three profile names. Unknown values: CLI exit 2; HTTP 400
`unknown policy profile`.

Default: **`ietf_current`**.

Facts (certificate key size, negotiated version, STARTTLS state) are recorded
regardless of profile. The pack decides whether a fact is a `Finding`. RSA-1024
is a certificate fact; a finding appears only when a rule fires.

## Profiles

| Profile | Pack file | Evaluation clock | Distinct behavior |
|---|---|---|---|
| `ietf_current` | `ietf_current.yaml` | `--analysis-time` (default now) | Current IETF-oriented rules. |
| `nist_federal` | `nist_federal.yaml` | `--analysis-time` | Same IETF-style rules **plus** `NIST_TLS_SUITE_NOT_APPROVED`. |
| `historical_at_capture` | `historical_at_capture.yaml` | `capture_start_time` | Dated rules, including time-bounded “discouraged” codes. Fails closed if capture start is missing. |

Pack metadata `version` is `"2026.09.0"`. `run_identity.policy_pack_version`
is the SHA-256 of canonical validated pack JSON, not that string.

**Deferred:** organization-specific packs (`organization_*`). They are not
loadable in this build.

## Service roles

All three packs classify sessions before applying role-scoped rules:

| Role | Payload protocol | Responder port |
|---|---|---|
| `smtp_relay` | smtp | 25 |
| `smtp_submission` | smtp | 465 or 587 |
| `imap_access` | imap | 143 or 993 |
| `pop3_access` | pop3 | 110 or 995 |

Ambiguous or nonstandard SMTP stays unclassified. Relay versus submission
policy is never guessed from a port alone. Handshake- and certificate-targeted
rules with empty `roles` still apply.

## `ietf_current`

Clock: analysis time. Rule ids include TLS version/cipher/key-exchange,
forward secrecy, certificate strength/path/identity, and mail cleartext /
STARTTLS fallback. Session findings are only **negative** or
**indeterminate**. Passes are retained as `policy_checks`, not as findings.

Representative codes (not the full pack):

- `TLS_NEGOTIATED_SSL3`, `TLS_NEGOTIATED_TLS10`, `TLS_NEGOTIATED_TLS11`
- `TLS_CIPHER_NULL`, `TLS_CIPHER_EXPORT`, `TLS_CIPHER_RC4`, `TLS_CIPHER_3DES`,
  `TLS_CIPHER_CBC`
- `TLS12_STATIC_RSA_NEGOTIATED`, `TLS12_STATIC_DH_NEGOTIATED`,
  `TLS12_DHE_NEGOTIATED`, `TLS12_STATIC_ECDH_NEGOTIATED`,
  `TLS12_DHE_PARAMETERS_LT2048`
- `TLS_HANDSHAKE_SIGNATURE_MD5`, `TLS_HANDSHAKE_SIGNATURE_SHA1`
- `TLS_FORWARD_SECRECY_ABSENT`, `TLS_FORWARD_SECRECY_INDETERMINATE`
- `CERT_RSA_KEY_LT2048`, `CERT_PUBLIC_KEY_STRENGTH_LT112`,
  `CERT_SIGNATURE_MD5`, `CERT_SIGNATURE_SHA1`, `CERT_EXPIRED_AT_CAPTURE`,
  `CERT_PATH_INVALID_AT_CAPTURE`, `CERT_IDENTITY_MISMATCH`,
  `CERT_BECAME_INVALID_AFTER_CAPTURE`
- `MAIL_SUBMISSION_CLEARTEXT`, `MAIL_ACCESS_CLEARTEXT`,
  `IMAP_LOGIN_WITHOUT_TLS`, `POP3_PASS_WITHOUT_TLS`,
  `UPGRADE_ACCEPTED_WITHOUT_TLS_TRANSITION`, `UPGRADE_PLAINTEXT_FALLBACK`

## `nist_federal`

Clock: analysis time. Adds one NIST-specific rule:

**`NIST_TLS_SUITE_NOT_APPROVED`** — the selected cipher suite is absent from
the SP 800-52 Rev. 2 approved tables. Severity for a negative outcome is
`medium`. Inline pack rationale: **not NIST-approved is not the same as
cryptographically weak**.

The pack’s own tests show the distinction:

- `TLS_CHACHA20_POLY1305_SHA256` → negative for this rule
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` → pass
- `TLS_RSA_WITH_AES_128_CBC_SHA` → **pass** for this NIST-approval rule

Static RSA AES is still subject to the shared `TLS12_STATIC_RSA_NEGOTIATED`
rule. The NIST rule does not relabel strong non-approved crypto as weak, and
it does not treat NIST-approved static RSA as “no cryptographic weakness.”

## `historical_at_capture`

Clock: `capture_preflight.capture_start_time` from capinfos. If that timestamp
is `null`, analyze exits 1.

Extra dated rules (inactive outside their window):

| Code | Window | Meaning |
|---|---|---|
| `TLS_NEGOTIATED_TLS10_DISCOURAGED` | `effective_from` 2015-05-01, `effective_until` 2021-03-01 | RFC 7525 SHOULD NOT TLS 1.0, before RFC 8996 MUST NOT. |
| `TLS_NEGOTIATED_TLS11_DISCOURAGED` | same | TLS 1.1. |
| `TLS12_STATIC_RSA_DISCOURAGED` | `effective_until` 2026-07-01 | Historical static-RSA discouragement window. |

`effective_from` is inclusive; `effective_until` is exclusive. After RFC 8996,
the current `TLS_NEGOTIATED_TLS10` / `TLS_NEGOTIATED_TLS11` codes still apply
when the capture clock is in their effective range.

## Dashboard upload

The React dropzone sends `policy_profile=ietf_current` unless the caller
passes another value. The UI does not currently expose a profile picker.
Operators can set the form field over HTTP:

```bash
curl -F file=@tests/fixtures/empty/capture.pcapng \
  -F policy_profile=nist_federal \
  http://127.0.0.1:8000/api/v1/analyses
```

See [API reference](../reference/api.md).

## Related pages

- [Interpret findings](interpret-findings.md)
- [Analyze captures](analyze-captures.md)
- [CLI reference](../reference/cli.md)
- [As-built evidence model](../reference/evidence-schema.md)

## Implementation anchors

- `src/securemail/domain/policies/rules/ietf_current.yaml`
- `src/securemail/domain/policies/rules/nist_federal.yaml`
- `src/securemail/domain/policies/rules/historical_at_capture.yaml`
- `src/securemail/adapters/reference_data/policy_packs.py`
- `src/securemail/domain/policies/rule_engine.py`

## Test evidence

- Fixture `tests/fixtures/tls13_psk_only_resumption/`
- Inline YAML `tests:` blocks in each pack
