---
status: current
audience: architect
authoritative_for: offline path validation and RFC 9525 SAN identity matching
last_verified: 2026-09-06
---

# Chain and identity validation

Path validity and `identity_match` are **independent** fields on
`CertificateValidation`. A trusted path with a wrong SAN is
`path_valid_at_*: true` and `identity_match: false`. A self-signed leaf can
still match SNI.

Validation is offline. Analysis workers never fetch AIA, OCSP, CRL, CT, or
DNS. The trust store is a hashed PEM snapshot in-tree.

Attached only to **server leaves** (`chain_index == 0`). Intermediates and
client certificates keep `validation: null`.

## Inputs

| Input | Source |
|---|---|
| Leaf DER + intermediates | Extracted certificates for the same UID and server role |
| Trust snapshot | `adapters/pki/trust-store-snapshot.pem`, profile `offline_v1` |
| Capture verification time | TLS observation timestamp from `ssl.log` `ts` |
| Analysis verification time | `--analysis-time` (default now, UTC) |
| Reference identity | `--expected-hostname` if set, else `ssl.log` `server_name` (SNI) |

`--expected-hostname` wins over observed SNI when both exist
(`reference_identity_source=configured`). Missing both → identity cannot be
evaluated.

Python `cryptography` `PolicyBuilder` is authoritative. Zeek
`validate-certs` is loaded as a cross-check only. The OpenSSL CLI adapter is
not on the analyze path.

## Outputs

`CertificateValidation` on the server leaf:

| Field | Notes |
|---|---|
| `certificate_observed` | `true` when this leaf DER was extracted |
| `syntax_valid` | Copied from the leaf fact; path is not evaluated when false |
| `path_valid_at_capture_time` / `path_valid_at_analysis_time` | Path-only checks at the two instants |
| `path_invalid_reasons_at_*` | Stable codes. Never a bare `false` without a reason |
| `identity_match` | RFC 9525 SAN matching. **No CN fallback** |
| `identity_mismatch_reasons` | `san_mismatch` or `san_missing` when match is false |
| `reference_identity` / `reference_identity_source` | Observed SNI (`sni`) or configured hostname (`configured`) |
| `revocation_status` | Always `unknown` in this build |
| `trust_profile_id` | `offline_v1` |
| `trust_store_digest` | Same digest as `run_identity.trust_store_digest` |
| `indeterminate_reasons` | `syntax_invalid_leaf`, `reference_identity_unavailable`, `capture_time_unavailable` |

Path reason codes include `self_signed`, `missing_intermediate`,
`untrusted_issuer`, `expired_at_verification_time`,
`not_yet_valid_at_verification_time`, `signature_verification_failed`,
`max_chain_depth_exceeded`, `invalid_extensions`, `syntax_invalid_leaf`,
`certificate_not_observed`, `capture_time_unavailable`.

## Evidence states

Validation booleans are not themselves `EvidenceState` values. Uncertainty
is recorded as:

- `null` on `identity_match` when no reference identity exists
- `null` on `path_valid_at_capture_time` when capture time is unavailable
- `indeterminate_reasons` on the validation object
- handshake `server_certificate_state=not_observable` when TLS 1.3 hid the
  cert — there is then **no** `CertificateValidation` row to mark “pass”

`not_observable` on the handshake certificate field means the leaf **cannot
be observed**. It is not a skipped identity check that should count as
compliant.

Revocation enum allows `good` / `revoked` / `unknown` / `stale`. Without
imported OCSP/CRL this build **always** writes `unknown`. That is not a
pass.

See [evidence states](../reference/evidence-states.md).

## Precedence rules

1. If the leaf is not syntax-valid → do not run `PolicyBuilder`. Record
   `syntax_valid=false`, revocation `unknown`, and
   `syntax_invalid_leaf` (plus `reference_identity_unavailable` if no
   hostname).
2. Path check at capture time only if `ts` is present; analysis-time path
   check always runs when the leaf parsed.
3. Identity matching uses SAN `dNSName` and `iPAddress` only:
   - No Common Name fallback
   - At most 32 SAN entries
   - DNS names IDNA-normalized, max 253 characters
   - Single left-most `*.` label wildcard only (RFC 9525 style);
     `*` elsewhere does not match
   - IP references match `iPAddress` SAN, not DNS
4. Path result and identity result are written independently. Neither
   overwrites the other.

`run_identity.trust_store_digest` is SHA-256 of the PEM snapshot bytes.
Changing anchors changes every fixture’s run identity.

## Uncertainty behavior

- Missing SNI and missing `--expected-hostname` → `identity_match=null`,
  reason `reference_identity_unavailable`. That is not a pass.
- Trusted path + wrong SAN (`cert_chain_san_mismatch`) → path true,
  identity false. CLI proof for this stage.
- Self-signed (`cert_chain_self_signed`) → path false with `self_signed`;
  identity can still match.
- Missing intermediate → path false with `missing_intermediate`.
- Public corpus `cert_chain_public_corpus`: path valid at capture, expired
  at analysis; SNI `www.heise.de`. Dual clocks are the point.
- Revocation unknown never becomes `good` by timeout or by “no CRL in the
  PCAP.”

Policy predicates that read `certificate.validation.identity_match` see
`null` as unusable (unknown coverage), not as pass. See
[policy evaluation](policy-evaluation.md).

## Security bounds

| Bound | Value |
|---|---|
| Trust-store file | 2 MiB / 256 anchors |
| Chain depth | 16 |
| SAN entries considered | 32 |
| DNS name | 253 characters |
| Network from worker | none — no AIA/OCSP/CRL/CT/DNS |

EE extension policy is `ExtensionPolicy.permit_all()`; CA policy is
`webpki_defaults_ca()`. Hostname matching is **not** done inside
`PolicyBuilder.verify`; identity is a separate function.

Do not log certificate serials beyond the bounded evidence field. Do not
attempt to decrypt or recover private keys.

## Fixture examples

| Case | Asserts |
|---|---|
| `cert_chain_lab_trusted` | Path valid at both instants; identity matches SNI; revocation `unknown` |
| `cert_chain_self_signed` | `path_valid_at_*: false` with `self_signed`; identity can still match |
| `cert_chain_missing_intermediate` | `path_valid_at_*: false` with `missing_intermediate` |
| `cert_chain_san_match` | Trusted path and `identity_match: true` |
| `cert_chain_san_mismatch` | Path valid, `identity_match: false`. CLI proof |
| `cert_chain_public_corpus` | Path valid at capture, expired at analysis; regression only |

Proof:

```bash
uv run securemail analyze tests/fixtures/cert_chain_san_mismatch/capture.pcapng
```

## Limitations

- **Implemented:** independent path and identity; dual verification times;
  RFC 9525 SAN; always-unknown revocation.
- **Known limitation:** lab trust store is a committed snapshot, not the
  operator’s production roots unless they replace that file and refresh
  fixture digests.
- **Unsupported:** CN fallback; online revocation; AIA chasing.
- **Deferred:** imported OCSP/CRL as first-class evidence (`good` / `revoked`
  / `stale` remain unused).

## Related pages

- [Certificate extraction](certificate-extraction.md)
- [Policy evaluation](policy-evaluation.md)
- [Policy packs](../reference/policy-packs.md)
- [Evidence states](../reference/evidence-states.md)

## Implementation anchors

- `src/securemail/domain/policies/pki/chain_validation.py`
- `src/securemail/domain/policies/pki/identity.py`
- `src/securemail/application/normalize_certificates.py` (`_validate_server_leaf`)
- `src/securemail/adapters/pki/trust_store.py`

## Test evidence

- `tests/test_certificate_chain_fixtures.py`
- `tests/unit/test_chain_validation.py`
- `tests/unit/test_identity.py`
- `tests/unit/test_trust_store.py`
