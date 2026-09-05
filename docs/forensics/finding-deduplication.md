---
status: current
audience: architect
authoritative_for: finding dedup key, securemail.scoring/v1 arithmetic, and coverage denominators
last_verified: 2026-09-06
---

# Finding deduplication, scoring, and coverage

Session-level `Finding` records are collapsed to endpoint findings, then
scored with a transparent integer contract `securemail.scoring/v1`. Coverage
denominators are published as `securemail.posture/v1`. Analyze always runs
this step. Inventory labels default to `unknown` unless supplied to
`securemail score`.

This is a **priority** score, not a universal risk percentage.

## Inputs

| Input | Source |
|---|---|
| Session-level `Finding[]` | [Policy evaluation](policy-evaluation.md) |
| `PolicyCheck[]` | Same; applicable pass/fail/unknown/not_observable |
| Optional `AssetContext[]` | Only on `securemail score` (`securemail.score_request/v1`) |

`securemail score` reads JSON bounded at 8 MiB. Invalid JSON, schema, or
oversize input exits 1. A missing path exits 2 (Typer).

Analyze does not infer exposure, criticality, or blast radius from the PCAP.

## Outputs

`PostureAssessment` on `EvidenceDocument` v2:

| Field | Meaning |
|---|---|
| `assessment_state` | `complete`, `limited`, or `none` |
| `risk_score` | Maximum endpoint priority; see below |
| `prioritized_findings` | Deduped, scored, ordered `ScoredEndpointFinding` |
| `coverage` | Overall, by protocol, by category, by protocol×category |

Each scored finding keeps `contributing_finding_ids` and
`contributing_occurrences` (session UIDs / record keys). Dedup never drops
those references.

## Evidence states

Dedup `basis_state` is the **weakest** basis among members used as the
primary set (negatives if any exist, else all members). Weakest rank:

`conflicting` < `incomplete` < `indeterminate` < `not_observable` <
`inferred` < `observed` < `verified`.

Confidence points in the score use that `basis_state`. `not_observable`
contributes **0** confidence points. It is not treated as verified.

Coverage:

- `pass` — assertion held
- `fail` — confirmed negative
- `unknown` — incomplete, conflicting, or indeterminate evidence (including
  designed-indeterminate outcomes)
- `not_observable` — the driving evidence state is `not_observable`

`unknown_count` and `not_observable_count` are never folded into
`passed_count`.

See [evidence states](../reference/evidence-states.md).

## Precedence rules

### Dedup key

Session findings that share

```text
(code, affected_endpoint, policy_profile, policy_pack_version)
```

collapse to one `EndpointFindingCluster`. Mixed policy packs are not merged.
Input order does not matter.

Cluster construction:

- Outcome is `negative` if any member is negative, else `indeterminate`.
- Severity is the maximum among the **primary** set (negatives if present).
- Title/rationale/standards come from the representative (lowest
  `finding_id` among primary).
- `unique_occurrences` counts distinct `(record_type, record_key)` pairs
  (first evidence reference, or the finding id).
- `recurrence_count` is the number of member findings (capped at 4096).
- Evidence references merge uniquely (max 1024).

Aggregate `finding_id` is SHA-256 of `endpoint|code|endpoint|profile|pack|`
plus sorted member ids.

### Scoring formula (`securemail.scoring/v1`)

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

Unknown inventory is an **explicit addend**. It is never treated as zero and
never invented from the PCAP. One occurrence (`n=1`) adds 0 recurrence
points; six unique occurrences hit the cap of 10.

### Ordering

Analyst order: score descending, then negative before indeterminate, then
severity descending (`high` > `medium` > `low` > `informational`), then
code, endpoint, and aggregate id.

### Coverage reconciliation

```text
applicable = passed + failed + unknown + not_observable
```

Genuine non-applicability (inactive rule, role mismatch, where-clause fail)
is omitted from `policy_checks` and therefore from these counts.

Protocols: `smtp` / `imap` / `pop3` / `unclassified`. Categories:
`transport` / `mail_protocol` / `tls_handshake` / `certificate`.

`assessment_state` is `none` when `applicable_count=0`, `limited` when
unknown or not_observable counts are positive, otherwise `complete`.

Report-level `risk_score` is the maximum endpoint priority. It is `0` only
when coverage is complete and there are no findings. It is `null` when there
are no findings and coverage is `none` or `limited`.

## Uncertainty behavior

- A capture with only `not_observable` checks is `limited`, not a clean
  bill of health.
- Recurrence uses **unique** occurrence keys, not raw finding list length,
  so duplicate references to the same session do not inflate points.
- Scoring fixtures include `low` severity; built-in YAML packs still emit
  `high` / `medium` / `informational` for most rules.

## Security bounds

| Bound | Value |
|---|---|
| Findings in a score request | 4096 |
| Policy checks | 16 384 |
| Asset contexts | 1024 |
| Contributors per cluster | 4096 |
| Merged evidence refs | 1024 |
| Score CLI input | 8 MiB |

No packet payloads enter this stage. Endpoint strings are already bounded
(300 characters).

## Fixture examples

JSON-only (no PCAP) under `tests/fixtures/synthetic_findings/`:

| Case | Asserts |
|---|---|
| `mixed_severity.json` | Hand-computed component vectors and analyst order |
| `many_low_severity_one_endpoint.json` | N session findings collapse to one endpoint finding |
| `recurring_sessions.json` | Recurrence points from unique sessions (`min(10, 2×(n−1))`) |
| `coverage_denominators.json` | Non-zero `unknown_count` / `not_observable_count`, not folded into passed |

PCAP proof that analyze emits v2 posture:

```bash
uv run securemail score tests/fixtures/synthetic_findings/mixed_severity.json

uv run securemail analyze tests/fixtures/tls13_psk_only_resumption/capture.pcapng \
  --policy-profile ietf_current --out out/policy.json
```

There are **71** PCAP fixture directories in total; scoring’s own proofs are
the synthetic JSON set above.

## Limitations

- **Implemented:** four-tuple dedup, named score components, four-way
  coverage, unknown inventory addends.
- **Known limitation:** analyze cannot attach CMDB exposure/criticality;
  those labels exist only on `securemail score`.
- **Unsupported:** folding unknown into passed; dropping contributing
  session refs; merging mixed policy packs.
- **Deferred:** organization-specific scoring tables.

## Related pages

- [Policy evaluation](policy-evaluation.md)
- [Scoring and coverage (user guide)](../user-guide/scoring-and-coverage.md)
- [Evidence states](../reference/evidence-states.md)
- [Evidence schema](../reference/evidence-schema.md)

## Implementation anchors

- `src/securemail/domain/findings/dedup.py`
- `src/securemail/domain/findings/scoring.py`
- `src/securemail/domain/findings/posture.py`
- `src/securemail/application/run_analysis.py` (`score_findings`)

## Test evidence

- `tests/test_scoring_fixtures.py`
- `tests/unit/test_dedup.py`
- `tests/unit/test_scoring.py`
- `tests/unit/test_posture.py`
