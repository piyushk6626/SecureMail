---
status: current
audience: user
authoritative_for: securemail.evidence/v2 JSON envelope
last_verified: 2026-09-06
---

# Evidence schema

`securemail analyze` writes one frozen Pydantic v2 `EvidenceDocument`
(`extra="forbid"`). Models live under
[`src/securemail/domain/evidence/`](../../src/securemail/domain/evidence/).

- `NORMALIZATION_SCHEMA_VERSION` is the literal `"v1"` (packet/flow/session/
  handshake/certificate facts).
- `EVIDENCE_DOCUMENT_SCHEMA_VERSION` / `schema_version` is `"v2"` (adds policy
  checks and posture).

Serialization: `model_dump(mode="json")` then `json.dumps` with sorted keys,
indent 2, `ensure_ascii=False`, trailing newline. On-disk field order is
alphabetical, not declaration order.

Evidence-state meanings are owned by [evidence states](evidence-states.md).

## Envelope

```text
EvidenceDocument
  schema_version: "v2"
  run_identity: AnalysisRun
  capture_preflight: CapturePreflight
  flows: Flow[]
  sessions: EmailSession[]
  handshakes: TlsHandshake[]
  certificates: CertificateEvidence[]
  findings: Finding[]
  policy_checks: PolicyCheck[]
  posture: PostureAssessment
```

Standalone TLS (no mail session) is retained in `handshakes`. Certificates are
a separate top-level array linked by Zeek `uid` and `chain_index`. `findings`
never mutate the evidence arrays.

### `AnalysisRun`

| Field | Type | Today |
|---|---|---|
| `capture_sha256` | 64 hex chars | SHA-256 of the intake file **before** analyzers run |
| `analyzer_bundle_digest` | 64 hex chars | SHA-256 of `tools/analyzer-bundle.lock` bytes |
| `normalization_schema_version` | `"v1"` | constant |
| `configuration_digest` | 64 hex chars | hash of the config dict plus the IANA snapshot digest and optional expected hostname |
| `analysis_time` | RFC 3339 UTC | `--analysis-time`, else now (seconds precision in JSON) |
| `policy_profile` | enum | `ietf_current` (default), `nist_federal`, or `historical_at_capture` |
| `policy_pack_version` | 64 hex chars | SHA-256 of canonical validated pack JSON |
| `trust_store_digest` | 64 hex chars | SHA-256 of `adapters/pki/trust-store-snapshot.pem` |

Idempotency key from the design (not a stored field):

```text
(capture_sha256, analyzer_bundle_digest, normalization_schema_version,
 policy_pack_version, trust_store_digest, configuration_digest)
```

Policy is **not** folded into `configuration_digest`.

### `CapturePreflight`

From capinfos, recorded before Zeek:

| Field | Meaning |
|---|---|
| `packet_count` | Number of packets |
| `file_time_precision` | `nanosecond` / `microsecond` / `millisecond` / `second` / token |
| `packet_size_limit` | File-header snaplen when present |
| `packet_size_limit_min_inferred` / `max_inferred` | Inferred snaplen range when capinfos reports one |
| `truncated_packets_present` | True when captured length is less than original length on any packet |
| `original_packet_bytes` | Sum of on-wire sizes when known |
| `capture_duration_seconds` | Duration when known |
| `capture_start_time` | Earliest packet time as UTC, or `null` |

`truncated_packets_present` is capture-wide. The flow classifier receives it as
`truncated_packets` on every flow. `historical_at_capture` requires
`capture_start_time`.

## `Flow`

TCP/IP connection evidence plus reconstruction verdict. Classifier:
[`classify_reconstruction`](../../src/securemail/domain/evidence/flow.py).

| Field | Notes |
|---|---|
| `uid` | Zeek connection UID (deterministic given `global_hash_seed`) |
| `orig` / `resp` | `{host, port}` |
| `proto` | `tcp`, `udp`, `icmp`, `icmp6`, `unknown` |
| `history` | Zeek `conn.log` history letters |
| `conn_state` | Zeek conn_state |
| `missed_bytes` | From `conn.log` |
| `orig_bytes` / `resp_bytes` | From `conn.log` |
| `reconstruction_quality` | `complete` \| `incomplete` \| `conflicting` |
| `reason_code` | Set when quality is not complete |
| `observed_conditions` | Recoverable facts that do not degrade quality |
| `gap_bytes` | Count of missing bytes when known |
| `gap_bytes_exact` | False when the count is not known exactly — never invent bytes |
| `conflicting_byte_ranges` | Half-open `[start, end)` ranges in relative TCP sequence space |
| `evidence_state` | complete→`observed`, incomplete→`incomplete`, conflicting→`conflicting` |

Non-TCP flows are `complete` unless the capture has truncated packets (then
`incomplete` / `snaplen_truncation`).

## `EmailSession`

Identification fields are **independent**: a test can assert
`port_hint != payload_evidence`.

| Field | Notes |
|---|---|
| `uid` | Same Zeek UID as the `Flow` |
| `protocol` | `smtp` \| `imap` \| `pop3` \| `null` if unidentified |
| `port_hint` | Well-known ports only: smtp `{25,465,587}`, imap `{143,993}`, pop3 `{110,995}`, else `none`. Responder port wins |
| `payload_evidence` | `smtp` \| `imap` \| `pop3` \| `indeterminate` \| `none` |
| `evidence_state` | Identity visibility (`observed` / `indeterminate` / `conflicting`) |
| `identification_confidence` | `0.5` on Zeek vs TShark disagreement; otherwise `null` |
| `corroboration` | `zeek` or `zeek+tshark` |
| `events` | Bounded, redacted `ProtocolEvent` list (max 256) |
| `explicit_upgrade` | STARTTLS/STLS assessment (always present after normalize) |
| `implicit_tls` | Implicit-TLS correlation (always present after normalize) |

Sessions with `payload_evidence=none` and no ambiguous banner are dropped,
unless the flow is on an implicit-TLS port with SSL evidence.

### `ProtocolEvent`

| Field | Notes |
|---|---|
| `direction` | `orig` or `resp` |
| `kind` | `request`, `reply`, `capability`, `starttls`, `confirmation`, `ambiguous_banner`, `unexpected` |
| `command` | Uppercased verb when present; max 32 chars |
| `argument` | Redacted to `<redacted>` for secret commands |
| `reply_code` | SMTP numeric code when present |
| `text` | Bounded (128 chars at Zeek; normalizer also redacts) |
| `frame_number` | Set when TShark matched the event or supplied the only copy |
| `source` | `zeek` or `tshark` |
| `tag` | IMAP tag from TShark when present |

Secret commands (arguments/text redacted): `AUTH`, `LOGIN`, `USER`, `PASS`,
`APOP`, `AUTHENTICATE`, `AUTH_ANSWER`, `**`, `MAIL`, `RCPT`.

### `ExplicitUpgrade`

| Field | Notes |
|---|---|
| `state` | `advertised` \| `requested` \| `accepted` \| `tls_established` \| `plaintext_fallback` \| `violation` \| `null` |
| `evidence_state` | `observed` if `state` is set, else `not_observable` |
| `evidence_frames` | Sorted frame numbers cited by the machine |
| `downgrade_consistent` | Capability exchange seen, STARTTLS/STLS **not** advertised, but upgrade still requested and accepted. Not proof of an attacker |

### `ImplicitTls`

| Field | Notes |
|---|---|
| `correlated_protocol` | Set only from **selected** ALPN `smtp` / `imap` / `pop3` |
| `evidence_state` | `observed` (ALPN), `indeterminate` (TLS on 465/993/995 without ALPN), `not_observable` otherwise |
| `source` | `alpn`, `none`, or `null` |
| `evidence_frames` | ClientHello frames when ALPN correlation succeeded |

Port number never sets `correlated_protocol`.

**Known limitation:** selected ALPN `smtp`/`imap`/`pop3` correlates as
`observed` on **any** responder port, not only 465/993/995. See
[known limitations](../status/known-limitations.md).

## `TlsHandshake`

Linked to a `Flow` by Zeek `uid`. Cipher names and codes come from the
checked-in IANA snapshot.

| Field | Notes |
|---|---|
| `uid` | Same Zeek UID as the `Flow` |
| `ssl_history` | Zeek letter sequence; `messages` reconstruct it letter-for-letter |
| `established` / `resumed` | From Zeek `ssl.log` |
| `hello_retry_request` | True when history has `j` or a TShark ServerHello is classified as HRR |
| `visibility` | `full`, `partial`, or `not_observable` |
| `version.selected` | Negotiated version. `server_supported_version` wins over legacy `version`. Never inferred from ClientHello offers |
| `version.source` | `supported_versions` or `legacy_record` |
| `cipher_suite` | Canonical IANA `name` + `code` |
| `key_exchange` | Version-aware classifier |
| `messages` | Ordered handshake/record kinds with optional `frame_number` |
| `server_certificate_state` / `certificate_verify_state` | From history letters `x` / `y` only. TLS 1.3 post-ServerHello is `not_observable` unless those letters are present |
| `certificate_verify_signature` | Handshake `CertificateVerify` algorithm, **not** the X.509 certificate signature |
| `evidence_state` | Handshake-level visibility |

TLS 1.2 key exchange is **inferred** from the IANA suite-name grammar. TLS 1.3
key exchange comes from `key_share` / groups / PSK modes — **never** from the
cipher-suite name. PSK-only resumption is `PSK`; PSK with a selected key_share
is `PSK-(EC)DHE`.

TLS 1.3 visibility is `partial` unless both certificate and `CertificateVerify`
are actually observed. A truncated handshake that stops after ClientHello has
`version.selected=null` and `evidence_state=incomplete`.

## `CertificateEvidence`

Built from Zeek-extracted DER. `x509.log` is a cross-check only. TShark is
never the source of certificate bytes.

| Field | Notes |
|---|---|
| `der_sha256` | SHA-256 of the extracted DER; content-addressed store key |
| `uid` | Same Zeek UID as the `Flow` / `TlsHandshake` |
| `chain_index` | 0 = leaf, then intermediates in `ssl.log` `cert_chain_fps` order |
| `role` | `server` or `client` |
| `source_frames` | Certificate handshake frames when TShark attached them |
| `syntax_valid` | `false` with `syntax_error` on malformed/truncated/hostile ASN.1 |
| `subject` / `issuer` | RFC 4514 strings, bounded |
| `not_before` / `not_after` | UTC instants from the certificate |
| `valid_at_capture_time` | Inclusive RFC 5280 window vs the TLS observation timestamp |
| `valid_at_analysis_time` | Inclusive window vs `--analysis-time` |
| `expires_within_warning_window` | Remaining lifetime ≤ `--expiry-warning-days` (default 30) and not already expired |
| `public_key_algorithm` / `public_key_size` / `public_key_curve` | Parsed key facts |
| `effective_strength_bits` | RSA-2048 is 112-bit, P-256 is 128-bit |
| `signature_algorithm` | The certificate's own signature, never handshake `CertificateVerify` |
| `validation` | Leaf-only `CertificateValidation`. Intermediates and client certs are `null` |

Parser bounds: 64 KiB DER, 16 constructed ASN.1 levels, 256 certificates per
run, chain depth 16. TLS 1.3 handshakes without history letter `x` emit **no**
certificate records.

### `CertificateValidation`

Attached only to server leaves (`chain_index == 0`). Path validity and identity
are independent.

| Field | Notes |
|---|---|
| `certificate_observed` | `true` when this leaf DER was extracted |
| `syntax_valid` | Copied from the leaf fact; path is not evaluated when false |
| `path_valid_at_capture_time` / `path_valid_at_analysis_time` | Path-only check at the TLS observation timestamp and `--analysis-time` |
| `path_invalid_reasons_at_*` | Stable codes (`self_signed`, `missing_intermediate`, `expired_at_verification_time`, …) |
| `identity_match` | RFC 9525 SAN matching against SNI or `--expected-hostname`. **No CN fallback** |
| `identity_mismatch_reasons` | e.g. `san_mismatch`, `san_missing` |
| `reference_identity` / `reference_identity_source` | Observed SNI (`sni`) or configured hostname (`configured`) |
| `revocation_status` | Always `unknown` in this build (no imported OCSP/CRL) |
| `trust_profile_id` | `offline_v1` |
| `trust_store_digest` | Same digest as `run_identity.trust_store_digest` |
| `indeterminate_reasons` | When path or identity cannot be resolved |

Missing SNI and missing `--expected-hostname` make `identity_match` `null`, not
a pass. A trusted path with a wrong SAN is `path_valid_at_*: true` and
`identity_match: false`.

## `Finding`

Produced by the rule engine. Only **negative** and **indeterminate** outcomes
are serialized.

| Field | Notes |
|---|---|
| `finding_id` | SHA-256 of capture hash, profile, pack digest, rule id, outcome, target, record key |
| `code` | Stable rule id |
| `outcome` | `negative` or `indeterminate` |
| `severity` | `high` / `medium` / `low` / `informational` from the pack |
| `policy_profile` / `policy_pack_version` | Pack that produced the finding |
| `rule_effective_from` / `rule_effective_until` | Inclusive start; exclusive end when set |
| `policy_evaluation_time` | Analysis time, or capture start for `historical_at_capture` |
| `standards` | Cited RFC/NIST sections from YAML |
| `rationale` | Why the rule fired |
| `evidence_references` | Canonical pointers; no JSON array indexes |
| `basis_state` | Weakest contributing evidence state |
| `evaluation_state` | `verified` for negative, `indeterminate` for indeterminate |
| `affected_endpoint` | Endpoint the finding is attributed to |
| `remediation_id` | Pack remediation key |

`evidence_references[].field_path` uses engine paths such as
`handshake.version.selected` (qualified by record type). The dashboard resolver
walks paths relative to the already-selected record — see
[known limitations](../status/known-limitations.md).

## Posture and policy checks

See [scoring](../user-guide/scoring-and-coverage.md) for the v1 formula, dedup key, ordering, and
coverage vocabulary. `policy_checks` retain applicable
pass/fail/unknown/not-observable evaluations. `posture` holds endpoint-deduped
prioritized findings and coverage denominators (`securemail.posture/v1`).

## Example (shape, not a golden file)

A nonstandard-port POP3 session looks like: `port_hint=none`,
`payload_evidence=pop3`, `protocol=pop3`, `evidence_state=observed`,
`corroboration=zeek` (TShark dissectors do not bind off well-known ports). An
IMAP capability-stripped upgrade looks like `explicit_upgrade.state=accepted`,
`downgrade_consistent=true`. TLS on 993 without ALPN looks like
`protocol=null`, `payload_evidence=indeterminate`,
`implicit_tls.evidence_state=indeterminate`.

Committed examples: [`tests/fixtures/`](../../tests/fixtures/) — the harness
requires byte-for-field equality with `expected.json`.

## Related pages

- [Evidence states](evidence-states.md)
- [Report schema](report-schema.md)
- [Policy packs](policy-packs.md)
- [CLI](cli.md)

## Implementation anchors

- `src/securemail/domain/evidence/`
- `src/securemail/application/normalize_*.py`
- `src/securemail/domain/policies/rule_engine.py`

## Test evidence

- `tests/support/fixture_harness.py`
- Per-step `tests/test_*_fixtures.py`
