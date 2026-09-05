---
status: current
audience: architect
authoritative_for: per-certificate facts extracted from Zeek DER not policy findings
last_verified: 2026-09-06
---

# Certificate extraction

Step 5 records certificate **facts**. Policy (RSA-1024 is a finding, SHA-1
is a finding) is Step 7. Do not collapse those layers.

Zeek extracts DER. Python parses with `cryptography`. `x509.log` is a
cross-check only. TShark is never the source of certificate bytes.

## Inputs

| Source | Role |
|---|---|
| Zeek extract under `certs/*.der` | Authoritative bytes; copied into `ZeekRunResult.extracted_certificates` before the temp dir is deleted |
| `ssl.log` `cert_chain_fps` / `client_cert_chain_fps` | Chain order; index 0 is leaf |
| `sm_cert.log` / `files.log` | Fallback linkage by fuid when fingerprints are missing |
| `TlsHandshake` | TLS 1.3 UIDs without history letter `x` emit **no** certificate records |
| `--analysis-time` | Default now (UTC); analysis-time validity |
| TLS observation `ts` | Capture-time validity |
| `--expiry-warning-days` | Default 30 days |

MIME types extracted: `application/pkix-cert` and `application/x-x509-*`.
Opaque SSL files are also extracted so malformed Certificate messages still
fail closed as `syntax_valid=false`.

## Outputs

Top-level `CertificateEvidence` array, content-addressed by SHA-256 of DER:

| Field | Notes |
|---|---|
| `der_sha256` | Store key; sidecar `<out-dir>/certificates/<sha256>.der` |
| `uid` | Same Zeek UID as the flow / handshake |
| `chain_index` | 0 = leaf, then intermediates in `cert_chain_fps` order |
| `role` | `server` or `client` |
| `source_frames` | Certificate handshake frames when TShark attached them |
| `syntax_valid` / `syntax_error` | Malformed, truncated, or hostile ASN.1 |
| `subject` / `issuer` | RFC 4514 strings, bounded |
| `not_before` / `not_after` | UTC instants from the certificate |
| `valid_at_capture_time` | Inclusive RFC 5280 window vs the TLS observation timestamp |
| `valid_at_analysis_time` | Inclusive window vs `--analysis-time` |
| `expires_within_warning_window` | Remaining lifetime ≤ warning window **and** not already expired |
| `public_key_algorithm` / `public_key_size` / `public_key_curve` | Parsed key facts |
| `effective_strength_bits` | From `key_strength.py`; RSA-2048 is 112-bit, P-256 is 128-bit |
| `signature_algorithm` | The certificate’s own signature (for example `sha256WithRSAEncryption`) |
| `validation` | Leaf-only; see [chain and identity](chain-and-identity-validation.md). Intermediates and client certs are `null` |

RSA and ECC are never compared by raw bit length. Strength uses NIST SP
800-57 comparable floors.

## Evidence states

Certificate `evidence_state` is `observed` when DER was extracted and parsed
(even if `syntax_valid=false`, the observation of hostile/truncated bytes is
still recorded). TLS 1.3 handshakes without history letter `x` produce **no
row**: the corresponding handshake field is `server_certificate_state=
not_observable`. That means the certificate **cannot be observed** from this
passive capture, not that “certificates do not apply to TLS 1.3.”

`valid_at_capture_time` and `valid_at_analysis_time` are independent
booleans (or `null` when the window cannot be evaluated). A cert can be
valid at capture and expired at analysis (`cert_chain_public_corpus`).

Handshake `certificate_verify_signature` is **not** copied onto this
object. `cert_sha1_signed` records `sha1WithRSAEncryption` on the X.509
signature; `tls12_sha1_certificate_verify` records the handshake algorithm.

See [evidence states](../reference/evidence-states.md).

## Precedence rules

1. If the handshake exists, `server_certificate_state` is `not_observable`,
   and history has neither `x` nor `X` → skip the UID (no fabricated TLS 1.3
   leaves from `x509.log`).
2. Match `cert_chain_fps` fingerprints to extracted DER (SHA-256, then
   SHA-1).
3. If fingerprints are present but unmatched, do not invent certificates.
4. If fingerprints are empty but history contains `x`/`X`, fall back to
   `files.log` / `sm_cert.log` for that UID.
5. Parse DER with bounds **before** large `cryptography` allocation.
   Oversized or over-nested input is `syntax_valid=false`.
6. Compute the two validity booleans independently from `not_before` /
   `not_after`.
7. Attach `validation` only for server leaves when a trust snapshot is
   wired (production CLI always wires `adapters/pki/trust-store-snapshot.pem`).

Expiry warning is true only when the cert is not already expired and
remaining lifetime is ≤ the configured window.

## Uncertainty behavior

- Missing capture timestamp → `valid_at_capture_time` cannot be proven;
  chain validation records `capture_time_unavailable` on the leaf.
- Malformed ASN.1 still completes the run under analyzer resource limits
  (`cert_malformed_asn1`).
- Client certificates are facts with `validation=null`.
- Do not treat `syntax_valid=false` as “no certificate weakness”: it is
  incomplete PKI evidence, and policy sees unusable predicates rather than a
  pass.

## Security bounds

| Bound | Value | Constant |
|---|---|---|
| DER per file | 64 KiB | `MAX_CERTIFICATE_DER_BYTES` / Zeek `FileExtract::default_limit` |
| Certificates per run | 256 | `MAX_CERTIFICATES_PER_RUN` |
| ASN.1 constructed depth | 16 | `MAX_ASN1_DEPTH` |
| Chain depth | 16 | `MAX_CHAIN_DEPTH` |
| Combined Zeek output | 50 MiB | logs plus extracted DER |

Subject/issuer/serial strings are length-bounded. Extracted bytes are stored
by SHA-256; the CLI writes sidecars next to `--out`. Packet payloads and
private keys are not logged. TShark certificate fields are not allowlisted.

The OpenSSL CLI adapter is **test-only**. Production validation uses Python
`cryptography`. Never `/usr/bin/openssl` (LibreSSL) on macOS.

## Fixture examples

| Case | Asserts |
|---|---|
| `cert_valid_current` | Currently valid RSA-2048 SHA-256; both validity booleans true; strength 112-bit |
| `cert_expired_rsa1024` | Expired RSA-1024 fact; both validity booleans false; strength 80-bit. CLI proof |
| `cert_not_yet_valid` | Not-yet-valid window; both validity booleans false |
| `cert_ecdsa_p256` | ECDSA P-256; effective strength 128-bit |
| `cert_sha1_signed` | Certificate signature `sha1WithRSAEncryption`, kept separate from handshake CV |
| `cert_expiry_warning` | `analyze.json` freezes analysis time; `expires_within_warning_window=true` |
| `cert_malformed_asn1` | `syntax_valid=false` with a reason; completes under limits |
| `tls13_full_handshake` | No certificate records without history letter `x` |

Proof:

```bash
uv run securemail analyze tests/fixtures/cert_expired_rsa1024/capture.pcapng
```

## Limitations

- **Implemented:** DER extraction, dual validity clocks, comparable
  strength, syntax-fail-closed.
- **Known limitation:** TLS 1.3 certificates are usually absent in passive
  captures.
- **Unsupported:** AIA fetching, downloading missing intermediates, using
  TShark as a cert source.
- **Deferred:** storing full parsed SAN lists on the evidence object
  (identity matching still uses SAN internally at Step 6).

## Related pages

- [TLS handshakes](tls-handshakes.md)
- [Chain and identity validation](chain-and-identity-validation.md)
- [Policy evaluation](policy-evaluation.md)
- [Limits](../reference/limits.md)

## Implementation anchors

- `zeek/scripts/securemail-certs.zeek`
- `src/securemail/application/normalize_certificates.py`
- `src/securemail/domain/evidence/certificate.py`
- `src/securemail/domain/policies/pki/key_strength.py`
- `src/securemail/adapters/artifacts/certificate_store.py`

## Test evidence

- `tests/test_certificate_fixtures.py`
- `tests/unit/test_normalize_certificates.py`
- `tests/unit/test_parse_certificate.py`
- `tests/unit/test_key_strength.py`
