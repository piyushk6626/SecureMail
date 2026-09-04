# Evidence model (schema v0)

The CLI writes one `EvidenceDocument`. Models live under
[`src/securemail/domain/evidence/`](../src/securemail/domain/evidence/). They are
frozen Pydantic v2 models (`extra="forbid"`). `NORMALIZATION_SCHEMA_VERSION` is
the literal `"v0"`.

Serialization: `model_dump(mode="json")` then `json.dumps` with sorted keys, so
on-disk field order is alphabetical, not declaration order.

## Envelope

```text
EvidenceDocument
  schema_version: "v0"
  run_identity: AnalysisRun
  capture_preflight: CapturePreflight
  flows: Flow[]
  sessions: EmailSession[]
  handshakes: TlsHandshake[]
  certificates: CertificateEvidence[]
```

Standalone TLS (no mail session) is retained in `handshakes`. Certificates are
a separate top-level array linked by Zeek `uid` and `chain_index`. There is no
`findings` array.

### `AnalysisRun`

| Field | Type | Today |
|---|---|---|
| `capture_sha256` | 64 hex chars | SHA-256 of the intake file |
| `analyzer_bundle_digest` | 64 hex chars | SHA-256 of `tools/analyzer-bundle.lock` bytes |
| `normalization_schema_version` | `"v0"` | constant |
| `configuration_digest` | 64 hex chars | hash of the config dict plus the IANA snapshot digest |
| `policy_pack_version` | `str \| null` | always `null` |
| `trust_store_digest` | `str \| null` | always `null` |

Idempotency key from the design (not a stored field) is the tuple of those
digests. Policy and trust-store slots are reserved so later steps can fill them
without renaming the record.

### `CapturePreflight`

From capinfos, recorded before Zeek:

| Field | Meaning |
|---|---|
| `packet_count` | Number of packets |
| `file_time_precision` | `nanosecond` / `microsecond` / `millisecond` / `second` / token |
| `packet_size_limit` | File-header snaplen when present |
| `packet_size_limit_min_inferred` / `max_inferred` | Inferred snaplen range when capinfos reports one |
| `truncated_packets_present` | True when captured length &lt; original length on any packet |
| `original_packet_bytes` | Sum of on-wire sizes when known |
| `capture_duration_seconds` | Duration when known |

`truncated_packets_present` is a **capture-wide** flag. The flow classifier
receives it as `truncated_packets` on every flow in that run.

## Evidence states

Defined once in `domain/evidence/run.py` as `EvidenceState`. Every other
evidence model imports this enum; nothing redefines it.

| State | Meaning in this build |
|---|---|
| `observed` | Directly seen (complete TCP stream, confirmed protocol, terminal upgrade state with evidence) |
| `verified` | Reserved; not assigned by current classifiers |
| `inferred` | TLS 1.2 key exchange taken from the IANA suite-name grammar (and TLS 1.3 PSK-only when key_share is absent) |
| `incomplete` | Reconstruction missing bytes or boundaries; truncated ClientHello with no selected version |
| `conflicting` | Overlapping retransmission conflict, or Zeek vs TShark protocol disagreement |
| `not_observable` | Check does not apply (no upgrade attempt, implicit TLS not on 465/993/995) |
| `indeterminate` | Ambiguous banner, TLS on a mail port without selected ALPN, unresolved identity |

`not_observable`, `incomplete`, and `indeterminate` are **not** “secure” and
must not be treated as a pass. Fixture tests assert the state field itself.

## `Flow`

TCP/IP connection evidence plus reconstruction verdict. Classifier:
[`classify_reconstruction`](../src/securemail/domain/evidence/flow.py).

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
| `reason_code` | Set when quality is not complete; see [tcp-reconstruction.md](tcp-reconstruction.md) |
| `observed_conditions` | Recoverable facts that do not degrade quality |
| `gap_bytes` | Count of missing bytes when known |
| `gap_bytes_exact` | False when the count is not known exactly — never invent bytes |
| `conflicting_byte_ranges` | Half-open `[start, end)` ranges in relative TCP sequence space |
| `evidence_state` | Mapped from quality: complete→`observed`, incomplete→`incomplete`, conflicting→`conflicting` |

Non-TCP flows are `complete` unless the capture has truncated packets (then
`incomplete` / `snaplen_truncation`).

## `EmailSession`

Protocol-tagged session. Identification fields are **independent**: a test can
assert `port_hint != payload_evidence`.

| Field | Notes |
|---|---|
| `uid` | Same Zeek UID as the `Flow` |
| `protocol` | `smtp` \| `imap` \| `pop3` \| `null` if unidentified |
| `port_hint` | From well-known ports only: smtp `{25,465,587}`, imap `{143,993}`, pop3 `{110,995}`, else `none`. Responder port wins |
| `payload_evidence` | `smtp` \| `imap` \| `pop3` \| `indeterminate` \| `none` |
| `evidence_state` | Identity visibility (`observed` / `indeterminate` / `conflicting`) |
| `identification_confidence` | `0.5` on Zeek vs TShark disagreement; otherwise `null` |
| `corroboration` | `zeek` or `zeek+tshark` |
| `events` | Bounded, redacted `ProtocolEvent` list (max 256) |
| `explicit_upgrade` | STARTTLS/STLS assessment (always present after normalize) |
| `implicit_tls` | Implicit-TLS correlation (always present after normalize) |

Sessions with `payload_evidence=none` and no ambiguous banner are dropped,
unless the flow is on an implicit-TLS port with SSL evidence (those become
indeterminate or ALPN-identified sessions).

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
| `source` | `zeek` or `tshark` (SSL facts are not stored as events) |
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

Port number never sets `correlated_protocol`. See [starttls.md](starttls.md).

## `TlsHandshake`

Top-level TLS handshake evidence, linked to a `Flow` by Zeek `uid`. Built by
[`normalize_handshakes`](../src/securemail/application/normalize_handshakes.py)
from `ssl.log` / `ssl-log-ext` plus optional TShark handshake frames. Cipher
names and codes come from the checked-in IANA snapshot, not hardcoded suite
literals.

| Field | Notes |
|---|---|
| `uid` | Same Zeek UID as the `Flow` |
| `ssl_history` | Zeek letter sequence; `messages` reconstruct it letter-for-letter |
| `established` / `resumed` | From Zeek `ssl.log` |
| `hello_retry_request` | True when history has `j` or a TShark ServerHello is classified as HRR |
| `visibility` | `full`, `partial`, or `not_observable` |
| `version.selected` | Negotiated version. `server_supported_version` wins over legacy `version` / `server_version`. Never inferred from ClientHello offers |
| `version.source` | `supported_versions` or `legacy_record` |
| `cipher_suite` | Canonical IANA `name` + `code` (e.g. `TLS_AES_256_GCM_SHA384` / `0x1302`) |
| `key_exchange` | Version-aware classifier; see below |
| `messages` | Ordered handshake/record kinds with optional `frame_number` |
| `server_certificate_state` / `certificate_verify_state` | From history letters `x` / `y` only. TLS 1.3 post-ServerHello is `not_observable` unless those letters are present — never fabricated from `x509.log` |
| `certificate_verify_signature` | Handshake `CertificateVerify` algorithm, **not** the X.509 certificate signature. `not_observable` when history lacks `y`; `incomplete` when `y` is present but the selected algorithm is not decoded |
| `evidence_state` | Handshake-level visibility (`observed` / `incomplete` / `conflicting`) |

TLS 1.2 key exchange is **inferred** from the IANA suite-name grammar (`ECDHE`,
`RSA`, `ECDH`, …) plus observed `curve` / `dh_param_size`. TLS 1.3 key exchange
comes from `key_share` / groups / PSK modes / `resumed` only — **never** from
the cipher-suite name. PSK-only resumption is `PSK`; PSK with a selected
key_share is `PSK-(EC)DHE`.

TLS 1.3 visibility is `partial` unless both certificate and `CertificateVerify`
are actually observed. A truncated handshake that stops after ClientHello has
`version.selected=null` and `evidence_state=incomplete`.

## `CertificateEvidence`

Top-level certificate facts, linked to a handshake/flow by Zeek `uid`. Built by
[`normalize_certificates`](../src/securemail/application/normalize_certificates.py)
from Zeek-extracted DER bytes. `x509.log` is a cross-check only. TShark is never
the source of certificate bytes.

| Field | Notes |
|---|---|
| `der_sha256` | SHA-256 of the extracted DER; also the content-addressed store key |
| `uid` | Same Zeek UID as the `Flow` / `TlsHandshake` |
| `chain_index` | 0 = leaf, then intermediates in `ssl.log` `cert_chain_fps` order |
| `role` | `server` or `client` |
| `source_frames` | Certificate handshake frames when TShark attached them |
| `syntax_valid` | `false` with `syntax_error` on malformed/truncated/hostile ASN.1 |
| `subject` / `issuer` | RFC 4514 strings, bounded |
| `not_before` / `not_after` | UTC instants from the certificate |
| `valid_at_capture_time` | Inclusive RFC 5280 window vs the TLS observation timestamp |
| `valid_at_analysis_time` | Inclusive window vs `--analysis-time` (default: now, UTC) |
| `expires_within_warning_window` | Remaining lifetime ≤ `--expiry-warning-days` (default 30) and not already expired |
| `public_key_algorithm` / `public_key_size` / `public_key_curve` | Parsed key facts |
| `effective_strength_bits` | From [`key_strength.py`](../src/securemail/domain/policies/pki/key_strength.py); RSA-2048 is 112-bit, P-256 is 128-bit |
| `signature_algorithm` | The certificate's own signature (e.g. `sha256WithRSAEncryption`), never the handshake `CertificateVerify` algorithm |

Parser bounds: 64 KiB DER, 16 constructed ASN.1 levels, 256 certificates per
run. Oversized or over-nested input is `syntax_valid: false` without calling
into a large `cryptography` allocation.

TLS 1.3 handshakes without history letter `x` emit no certificate records.

## Example (shape, not a golden file)

A nonstandard-port POP3 session looks like: `port_hint=none`,
`payload_evidence=pop3`, `protocol=pop3`, `evidence_state=observed`,
`corroboration=zeek` (TShark dissectors do not bind off well-known ports). An
IMAP capability-stripped upgrade looks like `explicit_upgrade.state=accepted`,
`downgrade_consistent=true`. TLS on 993 without ALPN looks like
`protocol=null`, `payload_evidence=indeterminate`,
`implicit_tls.evidence_state=indeterminate`.

Committed examples: [`tests/fixtures/`](../tests/fixtures/) — the harness
requires byte-for-field equality with `expected.json`.

## Not in this build

No path validation, SAN identity matching, or revocation (Step 6). No `Finding`.
`verified` is a legal enum member but unused by current classifiers. Handshake
and certificate records do not judge weak suites or forward secrecy.
