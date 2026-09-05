---
status: current
audience: architect
authoritative_for: TLS version, cipher, key-exchange classification and handshake visibility
last_verified: 2026-09-06
---

# TLS handshakes

Handshake evidence is a top-level `TlsHandshake` linked to a `Flow` by Zeek
`uid`. Zeek is the parameter source (`ssl.log` plus `ssl-log-ext`). TShark
supplies frame numbers, HelloRetryRequest corroboration, and
CertificateVerify signature schemes. Cipher names and codes come from the
checked-in IANA snapshot, not hardcoded suite literals.

Python does not decode TLS records.

## Inputs

| Source | Fields |
|---|---|
| `ssl.log` / ssl-log-ext | `ssl_history`, `version`, `server_version`, `server_supported_version`, `client_supported_versions`, `cipher`, `curve`, `server_key_share_group`, `client_key_share_groups`, `psk_key_exchange_modes`, `dh_param_size`, `established`, `resumed`, `last_alert` |
| `Flow` | Reconstruction quality (conflicting / selected incomplete reasons) |
| IANA snapshot | Cipher name ↔ code, group code ↔ name |
| Optional TShark | `tls.handshake.type`, `tls.handshake.extensions_key_share_selected_group`, `tls.handshake.sig_hash_alg` |

Display filter (current code): `smtp or imap or pop or tls.handshake`.
ADR 0001’s `tls.handshake.type == 1` is historical. The broader filter is
required so ServerHello (type 2, including HRR), Certificate, and
CertificateVerify (type 15) frames are present.

Standalone TLS (no mail session) is retained.

## Outputs

| Field | Notes |
|---|---|
| `ssl_history` | Zeek letter sequence; `messages` reconstruct it letter-for-letter |
| `established` / `resumed` | From Zeek `ssl.log` |
| `hello_retry_request` | True when history has `j` or a TShark ServerHello is classified as HRR (type 2 plus selected group) |
| `visibility` | `full`, `partial`, or `not_observable` |
| `version.selected` | Negotiated version. Never inferred from ClientHello offers |
| `version.source` | `supported_versions` or `legacy_record` |
| `cipher_suite` | Canonical IANA `name` + `code` (for example `TLS_AES_256_GCM_SHA384` / `0x1302`) |
| `key_exchange` | Version-aware classifier; no weakness or FS judgment |
| `messages` | Ordered handshake/record kinds with optional `frame_number` |
| `server_certificate_state` / `certificate_verify_state` | From history letters `x` / `y` only |
| `certificate_verify_signature` | Handshake `CertificateVerify` algorithm, **not** the X.509 certificate signature |
| `evidence_state` | Handshake-level visibility |

## Evidence states

Handshake-level `evidence_state`:

- `conflicting` if the flow reconstruction is conflicting
- `incomplete` if the flow is incomplete for snaplen/gap/capture-loss/midstream
  **and** the handshake is not `established`, or if version is incomplete
- `observed` when `version.selected` is set
- otherwise the version field’s state (`not_observable` if no ClientHello)

Version field:

| Situation | `version.evidence_state` |
|---|---|
| ServerHello present and `server_supported_version` decoded | `observed`, source `supported_versions` |
| ServerHello present, only legacy `version` / `server_version` | `observed`, source `legacy_record` |
| History has `C` but no ServerHello | `incomplete`, `selected=null` |
| No ClientHello | `not_observable`, `selected=null` |

TLS 1.3 certificates after ServerHello are `not_observable` unless history
letter `x` is present. `CertificateVerify` is `not_observable` unless letter
`y` is present. Those facts are **not** fabricated from `x509.log`. This is
the primary TLS illustration of “cannot be observed,” not “check does not
apply.”

When letter `y` is present but TShark did not decode a signature scheme, the
signature object is `incomplete`.

TLS 1.2 key exchange is `inferred` from the IANA suite-name grammar. TLS 1.3
ephemeral KX with a selected group is `observed`. TLS 1.3 PSK-only (resumed,
no key_share) is `inferred` when PSK modes indicate `psk_ke` (or no
`psk_dhe_ke`); otherwise PSK without key_share is `indeterminate`.

TLS 1.3 visibility is `partial` unless both certificate and
`CertificateVerify` are actually observed. Empty `ssl_history` is
`visibility=not_observable`.

See [evidence states](../reference/evidence-states.md).

## Precedence rules

### TLS version

`resolve_selected_version`:

1. If `server_supported_version` is present and history has ServerHello
   (`s` or HRR `j`) → selected from **supported_versions**.
2. Else if ServerHello and a legacy `server_version` / `version` exist →
   selected from **legacy_record**.
3. Else if ClientHello `C` → `selected=null`, `incomplete`.
4. Else `not_observable`.

`supported_versions` always wins over the legacy record-layer version.
ClientHello offered versions are recorded on
`client_supported_versions` and never become `selected`.

### TLS 1.3 key exchange

`classify_key_exchange` for TLS 1.3 uses `key_share` / groups / PSK modes /
`resumed` only — **never** the cipher-suite name
(`TLS_AES_*` / `TLS_CHACHA20_*` / `TLS_AEGIS_*` do not encode KX).

| Observation | `mechanism` |
|---|---|
| Resumed and a selected key_share/curve | `PSK-(EC)DHE` |
| Resumed, no key_share, psk_ke (or no psk_dhe_ke) | `PSK` |
| Resumed, no key_share, psk_dhe_ke offered | `PSK` with `indeterminate` |
| key_share selected, not resumed | `ECDHE` / `DHE` / `(EC)DHE` from group family |
| Client shares present, no selected server group | `null`, `incomplete` |

Group family: FFDHE codes 256–260 → `DHE`; hybrid/ML-KEM-ish labels or
codes ≥ 4585 → `(EC)DHE`; other named curves → `ECDHE`.

### TLS 1.2 key exchange

Longest-first prefixes in the IANA suite name after `TLS_`: `ECDHE_PSK`,
`DHE_PSK`, `RSA_PSK`, `ECDHE`, `DHE`, `ECDH`, `DH`, `PSK`, `RSA`, … State
is `inferred`. A TLS 1.3-looking suite name on a TLS 1.2 version is
`indeterminate`, not a KX guess from the AEAD name.

### Certificate vs CertificateVerify

- `server_certificate_state`: letter `x` → `observed`, else `not_observable`
- `certificate_verify_state`: letter `y` → `observed`, else `not_observable`
- `certificate_verify_signature.algorithm`: TShark type 15 +
  `tls.handshake.sig_hash_alg`

The X.509 `signature_algorithm` on `CertificateEvidence` is a different
field. SHA-1 in one does not imply SHA-1 in the other. Fixture
`tls12_sha1_certificate_verify` vs `cert_sha1_signed`.

## Uncertainty behavior

- Truncated ClientHello (`tls_truncated_client_hello`):
  `version.selected=null`, handshake `incomplete`. No guessed version.
- `tls_supported_versions_precedence`: selected TLS 1.2 from
  `supported_versions` while the legacy record is TLS 1.0.
- TLS 1.3 full handshake lab captures typically have encrypted certificates:
  `server_certificate_state=not_observable`, visibility `partial`. Do not
  invent leaves from `x509.log`.
- Missing IANA code for a named cipher: name kept, code `null`, cipher
  `inferred`.
- Handshake completeness does not repair TCP `conflicting` quality.

## Security bounds

| Bound | Value |
|---|---|
| Handshake rows | 10 000 |
| History length | bounded in the normalizer |
| TShark handshake types per frame | 16 |
| Excluded TShark fields | `tls.handshake.certificate`, `tls.handshake.extensions_key_share_key_exchange` |
| IANA snapshot | 1 MiB, 2048 ciphers, 512 groups; never fetched at analysis time |

Cipher identifiers are resolved through
`adapters/reference_data/iana-tls-parameters.json`. The snapshot SHA-256 is
part of `configuration_digest`.

## Fixture examples

| Case | Asserts |
|---|---|
| `tls12_ecdhe` | TLS 1.2, `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, KX `ECDHE` from suite grammar |
| `tls12_static_rsa` | `TLS_RSA_WITH_AES_128_CBC_SHA`, KX `RSA` |
| `tls12_static_ecdh` | KX `ECDH` |
| `tls13_full_handshake` | Version from `supported_versions`; KX from key_share, not cipher name; cert/CV `not_observable` |
| `tls13_hello_retry_request` | `hello_retry_request=true`, history `j`, HRR frame-linked |
| `tls13_psk_only_resumption` | Resumed handshake with KX `PSK` (not from cipher name) |
| `tls_supported_versions_precedence` | Selected TLS 1.2 from `supported_versions`; legacy record TLS 1.0 |
| `tls_truncated_client_hello` | `version.selected=null`, `incomplete` |
| `tls12_public_corpus` / `tls13_public_corpus` | Regression only |

Proof:

```bash
uv run securemail analyze tests/fixtures/tls13_hello_retry_request/capture.pcapng
```

## Limitations

- **Implemented:** supported_versions precedence; TLS 1.3 KX from key_share;
  HRR flag; Certificate vs CertificateVerify split.
- **Known limitation:** TLS 1.3 post-ServerHello certificates are usually
  `not_observable` in passive PCAPs without secrets.
- **Unsupported:** decrypting TLS; using cipher-suite name as TLS 1.3 KX;
  treating ClientHello offers as the negotiated version.
- **Deferred:** ticket lifetime / DHE reuse detection from one capture.

Forward secrecy consumes these facts; it does not live on `TlsHandshake`.
See [forward secrecy](forward-secrecy.md).

## Related pages

- [Certificate extraction](certificate-extraction.md)
- [Forward secrecy](forward-secrecy.md)
- [Policy evaluation](policy-evaluation.md)
- [Evidence states](../reference/evidence-states.md)
- [IANA / toolchain](../reference/toolchain.md)

## Implementation anchors

- `src/securemail/application/normalize_handshakes.py`
- `src/securemail/domain/evidence/handshake.py`
- `src/securemail/domain/policies/tls/key_exchange.py`
- `src/securemail/adapters/reference_data/iana_tls_parameters.py`

## Test evidence

- `tests/test_tls_fixtures.py`
- `tests/unit/test_normalize_handshakes.py`
- `tests/unit/test_key_exchange.py`
