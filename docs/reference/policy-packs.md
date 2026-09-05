---
status: current
audience: user
authoritative_for: built-in policy pack ids, clocks, and rule lists
last_verified: 2026-09-06
---

# Policy packs

Built-in packs live under
[`src/securemail/domain/policies/rules/`](../../src/securemail/domain/policies/rules/).
The engine loads YAML by `PolicyProfile` enum. There is **no** operator path
to a fourth pack. Organization packs are **Deferred**.

Schema: `securemail.policy/v1`. Pack human version: `2026.09.0`.
`run_identity.policy_pack_version` is the SHA-256 of the canonical validated
pack JSON, not the YAML `version:` string.

| Profile | File | Evaluation clock | Extra rules vs IETF |
|---|---|---|---|
| `ietf_current` (default) | `ietf_current.yaml` | `analysis_time` | — |
| `nist_federal` | `nist_federal.yaml` | `analysis_time` | `NIST_TLS_SUITE_NOT_APPROVED`; omits some IETF weakness rules |
| `historical_at_capture` | `historical_at_capture.yaml` | `capture_start_time` | `TLS_NEGOTIATED_TLS10_DISCOURAGED`, `TLS_NEGOTIATED_TLS11_DISCOURAGED`, `TLS12_STATIC_RSA_DISCOURAGED` |

`historical_at_capture` without `capture_start_time` is an `AnalysisError`
(exit 1). Policy is **not** folded into `configuration_digest`.

SMTP relay (port 25) ≠ submission (465/587) ≠ IMAP/POP3 access. Roles
`smtp_relay`, `smtp_submission`, `imap_access`, and `pop3_access` are defined
in each pack. “Not FIPS-approved” is not the same as “cryptographically weak”.

Only **negative** and **indeterminate** outcomes become `Finding` records.
Pass/present results stay in `policy_checks` and YAML inline tests.

## Shared rule ids (`ietf_current`)

Transport / TLS:

- `TLS_NEGOTIATED_SSL3`
- `TLS_NEGOTIATED_TLS10`
- `TLS_NEGOTIATED_TLS11`
- `TLS_CIPHER_NULL`
- `TLS_CIPHER_EXPORT`
- `TLS_CIPHER_RC4`
- `TLS_CIPHER_3DES`
- `TLS_CIPHER_CBC`
- `TLS12_STATIC_RSA_NEGOTIATED`
- `TLS12_STATIC_DH_NEGOTIATED`
- `TLS12_DHE_NEGOTIATED`
- `TLS12_STATIC_ECDH_NEGOTIATED`
- `TLS12_DHE_PARAMETERS_LT2048`
- `TLS_HANDSHAKE_SIGNATURE_MD5`
- `TLS_HANDSHAKE_SIGNATURE_SHA1`
- `TLS_FORWARD_SECRECY_ABSENT`
- `TLS_FORWARD_SECRECY_INDETERMINATE`

Certificates:

- `CERT_RSA_KEY_LT2048`
- `CERT_PUBLIC_KEY_STRENGTH_LT112`
- `CERT_SIGNATURE_MD5`
- `CERT_SIGNATURE_SHA1`
- `CERT_EXPIRED_AT_CAPTURE`
- `CERT_PATH_INVALID_AT_CAPTURE`
- `CERT_IDENTITY_MISMATCH`
- `CERT_BECAME_INVALID_AFTER_CAPTURE`

Mail:

- `MAIL_SUBMISSION_CLEARTEXT`
- `MAIL_ACCESS_CLEARTEXT`
- `IMAP_LOGIN_WITHOUT_TLS`
- `POP3_PASS_WITHOUT_TLS`
- `UPGRADE_ACCEPTED_WITHOUT_TLS_TRANSITION`
- `UPGRADE_PLAINTEXT_FALLBACK`

## `nist_federal` differences

**Implemented** extra rule:

- `NIST_TLS_SUITE_NOT_APPROVED` — negotiated suite must be in the pack’s
  approved-name list (SP 800-52 aligned). Severity `medium`. Not a claim that
  an unlisted suite is cryptographically broken.

**Omitted** relative to `ietf_current` (NIST still allows or treats elsewhere):

- `TLS_CIPHER_CBC`
- `TLS12_STATIC_RSA_NEGOTIATED`
- `TLS12_STATIC_DH_NEGOTIATED`
- `TLS12_DHE_NEGOTIATED`

Static RSA can still produce `TLS_FORWARD_SECRECY_ABSENT`. Switching
`tls12_static_rsa` between `ietf_current` and `nist_federal` reuses one PCAP.

## `historical_at_capture` extra rules

Effective-dated **DISCOURAGED** rules (SHOULD NOT era, exclusive `effective_until`):

| Rule | Window | Standard cited |
|---|---|---|
| `TLS_NEGOTIATED_TLS10_DISCOURAGED` | 2015-05-01 inclusive → 2021-03-01 exclusive | RFC 7525 §3.1.1 |
| `TLS_NEGOTIATED_TLS11_DISCOURAGED` | same | RFC 7525 §3.1.1 |
| `TLS12_STATIC_RSA_DISCOURAGED` | 2015-05-01 inclusive → 2026-07-01 exclusive | RFC 7525 §4.2 / RFC 9325 §4.2 |

After RFC 8996, the **MUST NOT** rules (`TLS_NEGOTIATED_TLS10` /
`TLS_NEGOTIATED_TLS11`) remain in the pack. Inline tests assert the
discouraged rules become inactive after their `effective_until`.

## Related pages

- [CLI `--policy-profile`](cli.md)
- [Standards](standards.md)
- [Policy development](../development/policy-development.md)
- [Policy evaluation](../forensics/policy-evaluation.md)

## Implementation anchors

- `src/securemail/domain/policies/rules/*.yaml`
- `src/securemail/domain/policies/rule_engine.py`
- `src/securemail/adapters/reference_data/policy_packs.py`

## Test evidence

- `tests/unit/test_policy_packs.py`
- `tests/unit/test_rule_engine.py`
- `tests/test_policy_fixtures.py`
