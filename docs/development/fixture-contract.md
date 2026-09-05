---
status: current
audience: contributor
authoritative_for: fixture directory contract and catalog tables
last_verified: 2026-09-06
---

# Fixture contract

Every deterministic PCAP case is a directory:

```text
tests/fixtures/<case_id>/
  capture.pcapng    # git-lfs; never edited after creation
  expected.json     # authored before code; harness requires exact match
  provenance.json   # source, generator, tool versions, sha256, created_at
  analyze.json      # optional CLI flags (analysis time, hostname, policy profile)
```

`<case_id>` is `<protocol_or_area>_<condition>` as named in the completed
build plan. There are **71** committed PCAP fixture directories.

[`tests/support/fixture_harness.py`](../../tests/support/fixture_harness.py)
`run_fixture(case_id)` invokes `analyze` with `--analysis-time` pinned to
`2026-09-04T12:00:00Z` when `analyze.json` omits it. `diff_json` treats
`null` vs missing key as a mismatch. Nothing is ignored.

Treat every capture, banner, certificate string, and report field as
**hostile**. Bound parser size/nesting.

## Non-PCAP fixtures

Step 8 scoring (JSON-only):

```text
tests/fixtures/synthetic_findings/
  mixed_severity.json
  many_low_severity_one_endpoint.json
  recurring_sessions.json
  coverage_denominators.json
  expected.json
  provenance.json
```

Step 9 reports (schema-first golden, no PCAP):

```text
tests/fixtures/reports/
  golden_report.json
  provenance.json
  assemble.py
```

Step 10 advisory ML (seeded synthetic cohort, no PCAP):

```text
tests/support/synthetic_cohorts/
  __init__.py                 # generator (locked seed 20260904)
  cohort_seeded_v1/
    manifest.json
    labels.json
    windows.json
```

Step 11 dashboard catalog:

```text
tests/fixtures/dashboard/
  catalog.json
  *.report.json
  jobs/
  ml_history/windows.jsonl
  assemble.py
```

PDF bytes are not goldened. HTML and PDF are rendered from the golden object
at test time.

## Provenance sources

| `source` | Used for |
|---|---|
| `lab` | Real stacks (Postfix/Dovecot-style servers, openssl, ALPN) |
| `scapy` | Malformations and capture-quality cases a real stack will not emit on demand |
| `public_corpus` | Regression only; never the sole proof of a rule |

## Catalog

### Step 0 — pipeline

| Case | Source | Asserts |
|---|---|---|
| `empty` | scapy | Schema-valid document; ICMP/TCP/UDP flows; `sessions=[]`; digests present; rerun byte-identical |

### Step 1 — TCP reconstruction

| Case | Source | `reconstruction_quality` / notes |
|---|---|---|
| `tcp_smtp_clean_baseline` | lab | `complete`, `gap_bytes=0`; also Step 2 SMTP/25 identity |
| `tcp_missing_syn` | scapy | `incomplete` / `missing_syn` |
| `tcp_missing_fin` | scapy | `incomplete` / `missing_fin` |
| `tcp_midstream_start` | scapy | `incomplete` / `midstream_start` |
| `tcp_snaplen_truncation` | scapy | `incomplete` / `snaplen_truncation`; never `complete` |
| `tcp_overlapping_retransmission_conflict` | scapy | `conflicting` / `overlapping_retransmission_conflict` |
| `tcp_out_of_order_segments` | scapy | `complete` + `out_of_order_segments` |
| `tcp_duplicate_segments` | scapy | `complete` + `duplicate_segments` |

### Step 2 — protocol identification

| Case | Source | Identity |
|---|---|---|
| `tcp_smtp_clean_baseline` | lab | smtp / port_hint smtp (port 25) |
| `smtp_submission_port` | lab | smtp on 587 |
| `imap_standard_port` | lab | imap on 143 |
| `pop3_standard_port` | lab | pop3 on 110 |
| `smtp_nonstandard_port` | scapy | smtp, `port_hint=none`; also Step 3 `advertised` |
| `imap_nonstandard_port` | scapy | imap, `port_hint=none`; also Step 3 `advertised` |
| `pop3_nonstandard_port` | scapy | pop3, `port_hint=none`; also Step 3 `advertised` |
| `email_ambiguous_banner` | scapy | `protocol=null`, `payload_evidence=indeterminate`, `port_hint=smtp` |
| `smtp_public_corpus` | public_corpus | smtp regression |
| `imap_public_corpus` | public_corpus | imap regression |

### Step 3 — STARTTLS / STLS / implicit TLS

| Case | Source | Upgrade / implicit |
|---|---|---|
| `smtp_starttls_success` | lab | `tls_established` |
| `imap_starttls_success` | lab | `tls_established` |
| `pop3_stls_success` | lab | `tls_established` |
| `smtp_implicit_tls` | lab | ALPN smtp, `implicit_tls.observed` |
| `imap_implicit_tls` | lab | ALPN imap |
| `pop3_implicit_tls` | lab | ALPN pop3 |
| `tls_mail_port_no_alpn` | lab | TLS on 993, no ALPN → identity and implicit TLS `indeterminate` |
| `smtp_starttls_rejected` | scapy | `requested` (not `tls_established`) |
| `imap_starttls_rejected` | scapy | `requested` |
| `pop3_stls_rejected` | scapy | `requested` |
| `smtp_starttls_capability_stripped` | scapy | `accepted`, `downgrade_consistent=true` |
| `imap_starttls_capability_stripped` | scapy | same (Step 3 proof case) |
| `pop3_stls_capability_stripped` | scapy | same |
| `smtp_starttls_mid_transition_violation` | scapy | `violation` |
| `imap_starttls_mid_transition_violation` | scapy | `violation` |
| `pop3_stls_mid_transition_violation` | scapy | `violation` |
| `smtp_plaintext_auth_after_failed_upgrade` | scapy | `plaintext_fallback` |
| `imap_plaintext_login_after_failed_upgrade` | scapy | `plaintext_fallback` |
| `pop3_plaintext_auth_after_failed_upgrade` | scapy | `plaintext_fallback` |
| `smtp_starttls_public_corpus` | public_corpus | STARTTLS regression |
| `imap_starttls_public_corpus` | public_corpus | STARTTLS regression |
| `pop3_stls_public_corpus` | public_corpus | STLS regression |

### Step 4 — TLS version / cipher / key exchange

| Case | Source | Asserts |
|---|---|---|
| `tls12_ecdhe` | lab | TLS 1.2, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, KX `ECDHE` from suite grammar |
| `tls12_static_rsa` | lab (OpenSSL 1.0.2u) | `TLS_RSA_WITH_AES_128_CBC_SHA`, KX `RSA` |
| `tls12_static_ecdh` | lab (OpenSSL 1.0.2u) | `TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA`, KX `ECDH` |
| `tls12_legacy_weak_suite` | lab (OpenSSL 1.0.2u) | `TLS_RSA_WITH_RC4_128_SHA` extracted; no policy finding |
| `tls13_full_handshake` | lab | TLS 1.3 from `supported_versions`; KX from key_share, not cipher name; cert/`CertificateVerify` `not_observable` |
| `tls13_hello_retry_request` | lab | `hello_retry_request=true`, history `j`, HRR frame-linked |
| `tls13_psk_only_resumption` | lab | A resumed handshake with KX `PSK` (not from cipher name) |
| `tls_supported_versions_precedence` | scapy | Selected TLS 1.2 from `supported_versions` while legacy record is TLS 1.0 |
| `tls_truncated_client_hello` | scapy | `version.selected=null`, `incomplete`; no guessed version |
| `tls12_public_corpus` | public_corpus | TLS 1.2 regression |
| `tls13_public_corpus` | public_corpus | TLS 1.3 regression |

### Step 5 — Certificate facts

| Case | Source | Asserts |
|---|---|---|
| `cert_valid_current` | lab | Currently valid RSA-2048 SHA-256; both validity booleans true; strength 112-bit |
| `cert_expired_rsa1024` | lab | Expired RSA-1024 fact; both validity booleans false; strength 80-bit. CLI proof |
| `cert_not_yet_valid` | lab | Not-yet-valid window; both validity booleans false |
| `cert_ecdsa_p256` | lab | ECDSA P-256; effective strength 128-bit, not compared to RSA by raw bits |
| `cert_sha1_signed` | lab | Certificate signature `sha1WithRSAEncryption`, kept separate from handshake CV |
| `cert_expiry_warning` | lab | `analyze.json` freezes analysis time; `expires_within_warning_window=true` |
| `cert_malformed_asn1` | scapy | `syntax_valid=false` with a reason; completes under analyzer resource limits |
| `cert_chain_public_corpus` | public_corpus | Independent TLS 1.2 chain (≥2 certs), regression only; also Step 6 |

### Step 6 — chain validation and identity

| Case | Source | Asserts |
|---|---|---|
| `cert_chain_lab_trusted` | lab | Path valid at both instants; identity matches SNI; revocation `unknown` |
| `cert_chain_self_signed` | lab | `path_valid_at_*: false` with `self_signed`; identity can still match |
| `cert_chain_missing_intermediate` | lab | `path_valid_at_*: false` with `missing_intermediate` |
| `cert_chain_san_match` | lab | Trusted path and `identity_match: true` |
| `cert_chain_san_mismatch` | lab | Path valid, `identity_match: false`. CLI proof |
| `cert_chain_public_corpus` | public_corpus | Path valid at capture, expired at analysis; SNI `www.heise.de` |

### Step 7 — policy engine

| Case | Source | Asserts |
|---|---|---|
| `tls10_negotiated` | lab | `TLS_NEGOTIATED_TLS10` |
| `tls11_negotiated` | lab | `TLS_NEGOTIATED_TLS11` |
| `tls12_null_cipher` | lab | `TLS_CIPHER_NULL` |
| `tls12_export_cipher` | lab | `TLS_CIPHER_EXPORT` |
| `tls12_static_dh` | scapy | `TLS12_STATIC_DH_NEGOTIATED`, forward secrecy absent |
| `tls12_sha1_certificate_verify` | lab | Handshake SHA-1 CertificateVerify, not the X.509 signature |
| `cert_rsa1536` | lab | `CERT_RSA_KEY_LT2048` (RSA-2048 still passes the same rule) |

Reused: RC4 (`tls12_legacy_weak_suite`), static RSA/ECDH, ECDHE, TLS 1.3 PSK-only,
truncated ClientHello. Profile switch uses `tls12_static_rsa` under `ietf_current`
and `nist_federal` without duplicating the PCAP.

### Step 8 — scoring

| Case | Source | Asserts |
|---|---|---|
| `synthetic_findings/mixed_severity.json` | synthetic | Hand-computed component vectors and analyst order |
| `synthetic_findings/many_low_severity_one_endpoint.json` | synthetic | N session findings collapse to one endpoint finding |
| `synthetic_findings/recurring_sessions.json` | synthetic | Recurrence points from unique sessions |
| `synthetic_findings/coverage_denominators.json` | synthetic | Non-zero `unknown_count` / `not_observable_count`, not folded into passed |

## Directory count

Unique PCAP fixture directories: **71**. Plus `synthetic_findings/` (no capture).

`empty` (1) + TCP including baseline (8) + remaining Step 2 (9) + remaining
Step 3 (22) + Step 4 (11) + Step 5 (8) + Step 6 lab (5) + Step 7 new (7) = 71.

Some directories are reused as proof in more than one step.

## Related pages

- [Fixture generation](fixture-generation.md)
- [Golden updates](golden-updates.md)
- [Testing](testing.md)

## Implementation anchors

- `tests/support/fixture_harness.py`
- `tests/fixtures/`

## Test evidence

- Per-step `tests/test_*_fixtures.py`
