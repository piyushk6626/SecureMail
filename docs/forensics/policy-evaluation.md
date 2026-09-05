---
status: current
audience: architect
authoritative_for: tri-state policy predicates, findings vs policy_checks, and pack evaluation
last_verified: 2026-09-06
---

# Policy evaluation

Policy is YAML data applied to already-normalized evidence. The engine never
mutates flows, sessions, handshakes, or certificates. Unknown evidence is
not a pass.

Packs live under `src/securemail/domain/policies/rules/`. The catalog of
profiles, clocks, and rule identifiers is
[policy packs](../reference/policy-packs.md). This page owns evaluation
semantics.

Default profile: `ietf_current`. `nist_federal` adds NIST-approved
suite/key rules without relabeling strong non-approved crypto as weak.
`historical_at_capture` uses `capture_start_time` as the evaluation clock
and **fails closed** if that timestamp is missing.

## Inputs

| Input | Source |
|---|---|
| Typed `PolicyPack` | YAML loaded and validated (`securemail.policy/v1`) |
| `pack_digest` | SHA-256 of canonical validated pack JSON → `policy_pack_version` |
| Evidence arrays | flows, sessions, handshakes, certificates |
| Evaluation time | Analysis time, or capture start for `historical_at_capture` |
| Derived facts | `service_role`, `forward_secrecy`, `observed_commands`, `transport_tls_established` |

Predicates may only name paths in `ALLOWED_PATHS` (depth ≤ 8). Unknown paths
are a pack error at load time, not a silent skip.

## Outputs

`evaluate_policy_batch` returns `PolicyEvaluation`:

| Array | Contains |
|---|---|
| `findings` | Session/handshake/certificate-level **negative** or **indeterminate** outcomes only |
| `policy_checks` | Applicable `pass` / `fail` / `unknown` / `not_observable` evaluations |

Passes and “present” results stay in `policy_checks` (and YAML inline tests).
They are not serialized as `Finding` records.

Each finding’s `finding_id` is SHA-256 of capture hash, profile, pack
digest, rule id, outcome, target, and record key.

## Evidence states

Predicate evaluation is tri-state: `pass`, `fail`, `unusable`.

A predicate is **unusable** when:

- `state_path` names an evidence state in `{incomplete, conflicting,
  not_observable, indeterminate}`, or
- the compared value is `null`

Unusable is **not** fail and **not** pass.

Coverage mapping:

| Engine result | `Finding` | `PolicyCheck.outcome` |
|---|---|---|
| assertion pass | omitted | `pass` |
| assertion fail (negative rule) | `outcome=negative`, `evaluation_state=verified` | `fail` |
| assertion fail with `fail_outcome=indeterminate` | `outcome=indeterminate` | `unknown` |
| assertion unusable | `outcome=indeterminate` | `unknown` or `not_observable` from the weakest driving state |
| where-clause unusable | no finding | same coverage outcome; rule result `not_applicable` |
| inactive rule, role mismatch, where fail | omitted entirely | omitted |

`basis_state` on a finding is the weakest contributing evidence state among
its references. `not_observable` as a driving state publishes coverage
`not_observable`, not a green check.

See [evidence states](../reference/evidence-states.md).

## Precedence rules

For each **active** rule and each target record:

1. If `day < effective_from` or `day >= effective_until` → skip (no check).
2. If `rule.roles` is non-empty and `derived.service_role` is not in that
   list → skip.
3. Evaluate `where` (AND of predicates).
   - fail → not applicable (omit)
   - unusable → coverage only, no finding
4. Evaluate `assertion` (AND of predicates).
   - pass → `policy_checks` pass
   - unusable → indeterminate finding + unknown/not_observable check
   - fail → negative or designed-indeterminate finding

### Service role

Roles are pack data. Built-in packs require payload-confirmed protocol
**and** responder port:

| Role | Protocol | Ports |
|---|---|---|
| `smtp_relay` | smtp | 25 |
| `smtp_submission` | smtp | 465, 587 |
| `imap_access` | imap | 143, 993 |
| `pop3_access` | pop3 | 110, 995 |

Zero matches → `unclassified`. More than one match → `indeterminate`.
Nonstandard-port SMTP therefore does not receive relay-only or
submission-only rules. Port is never enough without payload identity.

### Facts vs findings

Certificate extraction records “RSA-1024”. A YAML rule decides whether that
is `CERT_RSA_KEY_LT2048`. Handshake records KX `RSA`;
[forward secrecy](forward-secrecy.md) derives `absent`; YAML emits
`TLS_FORWARD_SECRECY_ABSENT`. Present FS is a passing `policy_check`, not a
finding.

SMTP relay (25) ≠ submission (465/587) ≠ IMAP/POP3 access. “Not
FIPS-approved” (`nist_federal`) ≠ “cryptographically weak.”

## Uncertainty behavior

- Unknown inventory and unknown evidence never count as passed coverage.
- Designed-indeterminate rules (PSK-only FS, truncated handshake) emit
  `Finding.outcome=indeterminate` and coverage `unknown`.
- `historical_at_capture` without `capture_start_time` raises
  `PolicyEngineError` (fail closed).
- Inline YAML tests (`tests:` on each rule) are evaluated against synthetic
  contexts at pack load; they are not PCAPs.

Organization-specific packs (`organization_*`) are not in this build.

## Security bounds

| Bound | Value |
|---|---|
| Pack file | 256 KiB |
| Rules per pack | 128 |
| Predicates per rule | 16 |
| Roles per pack | 16 |
| Inline tests per rule | 8 |
| Standards citations | 8 |
| Policy checks on the document | 16 384 |

Workers do not fetch policy, IANA, or trust data from the network. Pack
bytes are **not** folded into `configuration_digest`; they appear as
`policy_pack_version`.

## Fixture examples

| Case | Asserts |
|---|---|
| `tls10_negotiated` | `TLS_NEGOTIATED_TLS10` |
| `tls11_negotiated` | `TLS_NEGOTIATED_TLS11` |
| `tls12_null_cipher` | `TLS_CIPHER_NULL` |
| `tls12_export_cipher` | `TLS_CIPHER_EXPORT` |
| `tls12_static_dh` | `TLS12_STATIC_DH_NEGOTIATED`, FS absent |
| `tls12_sha1_certificate_verify` | Handshake SHA-1 CV, not the X.509 signature |
| `cert_rsa1536` | `CERT_RSA_KEY_LT2048` (RSA-2048 still passes the same rule) |
| `tls13_psk_only_resumption` | Step 7 CLI proof; FS indeterminate; `--policy-profile ietf_current` |
| `tls12_static_rsa` | Profile switch IETF vs NIST without duplicating the PCAP |

Reused captures: RC4 (`tls12_legacy_weak_suite`), static RSA/ECDH, ECDHE,
truncated ClientHello.

Proof:

```bash
uv run securemail analyze tests/fixtures/tls13_psk_only_resumption/capture.pcapng \
  --policy-profile ietf_current
```

## Limitations

- **Implemented:** three versioned packs; tri-state predicates; findings
  negative/indeterminate only; coverage checks retained.
- **Known limitation:** built-in YAML still emits `high` / `medium` /
  `informational` for most rules; `low` exists on `FindingSeverity` for
  scoring fixtures.
- **Unsupported:** using policy to rewrite evidence; treating unknown as
  pass; organization packs.
- **Deferred:** MTA-STS / DANE evaluation (would require imported
  enrichment, not live DNS).

## Related pages

- [Policy packs](../reference/policy-packs.md)
- [Forward secrecy](forward-secrecy.md)
- [Finding deduplication](finding-deduplication.md)
- [Evidence states](../reference/evidence-states.md)

## Implementation anchors

- `src/securemail/domain/policies/rule_engine.py`
- `src/securemail/domain/policies/rules/ietf_current.yaml`
- `src/securemail/domain/policies/rules/nist_federal.yaml`
- `src/securemail/domain/policies/rules/historical_at_capture.yaml`
- `src/securemail/adapters/reference_data/policy_packs.py`

## Test evidence

- `tests/test_policy_fixtures.py`
- `tests/unit/test_rule_engine.py`
- `tests/unit/test_policy_packs.py`
