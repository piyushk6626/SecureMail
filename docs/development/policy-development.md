---
status: current
audience: contributor
authoritative_for: how to change built-in YAML policy packs
last_verified: 2026-09-06
---

# Policy development

Packs are YAML data under
[`src/securemail/domain/policies/rules/`](../../src/securemail/domain/policies/rules/).
The engine is a pure function
([`rule_engine.py`](../../src/securemail/domain/policies/rule_engine.py)).
Facts vs findings: certificate/TLS normalizers record facts; YAML decides
whether a fact is a finding. Do not collapse those layers.

Bounds (see [limits](../reference/limits.md)): pack file 256 KiB, 128 rules,
16 predicates per rule.

## Workflow

1. Read the rule lists on [policy packs](../reference/policy-packs.md).
2. Add or change a rule in the owning YAML file. Include `effective_from`,
   severity for negative/indeterminate, `standards`, `remediation_id`, and
   inline `tests:` with `expected: negative|pass|indeterminate`.
3. Keep SMTP relay (25) ≠ submission (465/587) ≠ IMAP/POP3 access via `roles`.
4. Run pack unit tests, then named PCAP fixtures. Profile switches must reuse
   captures (`tls12_static_rsa` under `ietf_current` and `nist_federal`).
5. Regenerating goldens: [golden updates](golden-updates.md). Pack digest is
   part of `run_identity`.

Do not add an `organization_*` pack in this build. That is **Deferred**.

Forward secrecy lives in
[`forward_secrecy.py`](../../src/securemail/domain/policies/tls/forward_secrecy.py)
and is consumed by YAML: TLS 1.2 ECDHE/DHE present; static RSA/DH/ECDH absent;
TLS 1.3 (EC)DHE present; PSK-only or missing handshake indeterminate.

Missing evidence must yield `unknown` / `not_observable` coverage or an
`indeterminate` finding — never a silent pass.

## Related pages

- [Policy packs](../reference/policy-packs.md)
- [Standards](../reference/standards.md)
- [Fixture contract](fixture-contract.md)

## Implementation anchors

- `src/securemail/domain/policies/rules/*.yaml`
- `src/securemail/adapters/reference_data/policy_packs.py`

## Test evidence

- YAML `tests:` blocks
- `tests/unit/test_rule_engine.py`
- `tests/test_policy_fixtures.py`
