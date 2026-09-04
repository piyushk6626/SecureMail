# Scoring, dedup, and coverage (as built)

SecureMail publishes a **transparent integer priority**, not a universal
risk percentage. The contract is `securemail.scoring/v1` plus
`securemail.posture/v1`. Arithmetic lives in
[`src/securemail/domain/findings/scoring.py`](../src/securemail/domain/findings/scoring.py).

## Formula

```text
score = min(100, severity + confidence + exposure + recurrence
                + asset_criticality + blast_radius)
```

All addends are integers. The tables sum to 100 at the top of each range, so
the cap is natural.

| Component | Inputs | Points |
|---|---|---|
| severity | `high` / `medium` / `low` / `informational` | 50 / 30 / 15 / 0 |
| confidence | finding `basis_state` | verified 20, observed 16, inferred 12, incomplete 6, conflicting 3, indeterminate 2, not_observable 0 |
| exposure | inventory label, else `unknown` | public 10, partner 8, internal 5, isolated 2, unknown 4 |
| recurrence | unique occurrences of the same code on one endpoint | `min(10, 2 × (n − 1))` |
| asset criticality | inventory label, else `unknown` | critical 5, high 4, medium 3, low 1, unknown 2 |
| blast radius | inventory label, else `unknown` | organization 5, multi_asset 3, single_endpoint 1, unknown 1 |

Unknown inventory is an explicit addend. It is never treated as zero and never
invented from the PCAP.

## Dedup

Session-level `Finding` records that share `(code, affected_endpoint,
policy_profile, policy_pack_version)` collapse to one endpoint finding.
Recurrence count and every contributing finding/session reference are kept.
Mixed policy packs are not merged.

## Ordering

Analyst order is score descending, then negative before indeterminate, then
severity descending (`high` > `medium` > `low` > `informational`), then code,
endpoint, and aggregate id.

## Coverage

Applicable policy evaluations are retained as `policy_checks`:

- `pass` — assertion held
- `fail` — confirmed negative
- `unknown` — incomplete, conflicting, or indeterminate evidence (including
  designed-indeterminate outcomes)
- `not_observable` — the driving evidence state is `not_observable`

Genuine non-applicability (inactive rule, role mismatch, where-clause fail) is
omitted. `unknown_count` and `not_observable_count` are never folded into
`passed_count`. Totals reconcile:

```text
applicable = passed + failed + unknown + not_observable
```

Counts are published overall, per protocol (`smtp` / `imap` / `pop3` /
`unclassified`), per category (`transport` / `mail_protocol` / `tls_handshake`
/ `certificate`), and per protocol×category.

Report-level `risk_score` is the maximum endpoint priority. It is `0` only when
coverage is complete and there are no findings. It is `null` when there are no
findings and coverage is `none` or `limited`.

## Commands

```bash
# Score a synthetic finding set (stdout JSON)
uv run securemail score tests/fixtures/synthetic_findings/mixed_severity.json

# Analyze still emits findings plus policy_checks and posture on EvidenceDocument v2
uv run securemail analyze tests/fixtures/tls13_psk_only_resumption/capture.pcapng \
  --policy-profile ietf_current --out out/policy.json
```

`securemail score` reads `securemail.score_request/v1` JSON (findings, optional
policy checks, optional asset context), bounded at 8 MiB. Invalid JSON, schema,
or oversize input exits 1. A missing path exits 2 (Typer). Output is sorted-key
JSON on stdout.

Inventory labels are not inferred during `analyze`; they default to `unknown`
unless supplied to `score`.
