---
status: current
audience: user
authoritative_for: securemail.scoring/v1 and posture coverage denominators
last_verified: 2026-09-06
---

# Scoring and coverage

SecureMail publishes a **transparent integer priority**, not a universal risk
percentage. Contracts: `securemail.scoring/v1` and `securemail.posture/v1`.
Analyze always runs this step. Inventory labels on the analyze path default
to `unknown`. Supply labels only through `securemail score` JSON.

```bash
uv run securemail score tests/fixtures/synthetic_findings/mixed_severity.json
```

Score CLI input is bounded at 8 MiB. Invalid JSON, schema, or oversize input
exits 1. A missing path exits 2.

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

Session-level findings that share
`(code, affected_endpoint, policy_profile, policy_pack_version)` collapse to
one endpoint finding. Recurrence count and every contributing finding/session
reference are kept. Mixed policy packs are not merged.

## Ordering

Analyst order is score descending, then negative before indeterminate, then
severity descending (`high` > `medium` > `low` > `informational`), then code,
endpoint, and aggregate id.

## Coverage

Applicable policy evaluations are retained as `policy_checks`:

| Outcome | Meaning |
|---|---|
| `pass` | Assertion held |
| `fail` | Confirmed negative |
| `unknown` | Incomplete, conflicting, or indeterminate evidence (including designed-indeterminate outcomes) |
| `not_observable` | Driving evidence state is `not_observable` |

Genuine non-applicability (inactive rule, role mismatch, where-clause fail) is
**omitted**. `unknown_count` and `not_observable_count` are never folded into
`passed_count`.

```text
applicable = passed + failed + unknown + not_observable
```

Counts are published overall, per protocol (`smtp` / `imap` / `pop3` /
`unclassified`), per category (`transport` / `mail_protocol` / `tls_handshake`
/ `certificate`), and per protocol×category.

## Posture headline

`assessment_state`:

- `none` — no applicable checks
- `limited` — any `unknown` or `not_observable` checks
- `complete` — applicable checks with neither unknown nor not-observable

Report-level `risk_score` is the maximum endpoint priority. It is `0` only
when coverage is complete and there are no findings. It is `null` when there
are no findings and coverage is `none` or `limited`. A dash in the dashboard
KPI is that null, not a silent pass.

Coverage passed percentage in the UI is derived from these denominators. Unknown
and not-observable remain in the “Unknown / obscured” KPI.

## Related pages

- [Interpret findings](interpret-findings.md)
- [Generate reports](generate-reports.md)
- [CLI reference](../reference/cli.md)
- [Finding deduplication](../forensics/finding-deduplication.md)

## Implementation anchors

- `src/securemail/domain/findings/scoring.py`
- `src/securemail/domain/findings/dedup.py`
- `src/securemail/domain/findings/posture.py`
- `src/securemail/api/cli/commands/score.py`

## Test evidence

- `tests/unit/test_scoring.py`
- `tests/unit/test_dedup.py`
- `tests/unit/test_posture.py`
- `tests/test_scoring_fixtures.py`
