---
status: current
audience: contributor
authoritative_for: advisory ML evaluation harness and gates
last_verified: 2026-09-06
---

# ML evaluation

Advisory ML runs **after** deterministic findings. It never suppresses,
downgrades, or rewrites a `Finding`. `--advisory` is off by default.

Do not train on case evidence without separate authorization. Do not use raw
IPs/names/serials as supervised features. No autoencoders/sequence models in
this build. No LLM as a detector.

## Detectors

1. **Baseline** (always on when advisory runs): per-endpoint median/MAD and
   Page-Hinkley on rate features, plus peer-group categorical rarity.
2. **Isolation Forest**: in the tree only because the committed harness beat
   the baseline by the frozen margin. Do not add a second ML model until the
   same gate is rewritten and passed.

## Frozen gates

| Gate | Value |
|---|---|
| Detection delay | ≤ 2 daily windows |
| Top-K | 5 |
| Baseline precision@5 floor | 0.60 |
| Isolation Forest lift | +0.10 absolute |

Locked cohort:
[`tests/support/synthetic_cohorts/cohort_seeded_v1/`](../../tests/support/synthetic_cohorts/cohort_seeded_v1/)
(seed `20260904`). Development seed `20260101` is held out. History, rarity
tables, and Isolation Forest fits use **past windows only**.

```bash
uv sync --extra ml --extra dev
uv run securemail evaluate-ml tests/support/synthetic_cohorts/cohort_seeded_v1/
```

Exit 1 if any gate fails ([exit codes](../reference/exit-codes-and-errors.md)).

Dashboard worker: until 14 local endpoint-windows, publish
`ADVISORY_INSUFFICIENT_HISTORY`. Isolation Forest stays silent until 40
windows. A single capture with `--advisory` may emit `ADVISORY_NONE`.

Every anomaly needs a concrete, evidence-linked reason string. Generic
“anomaly detected” is a test failure.

**Known limitation:** `AdvisoryItem` keeps only `code` and `reason`; detector
metadata is dropped. See [known limitations](../status/known-limitations.md).

## Related pages

- [Report schema](../reference/report-schema.md)
- [CLI `evaluate-ml`](../reference/cli.md)

## Implementation anchors

- `src/securemail/domain/ml/evaluation.py`
- `src/securemail/application/advisory_pipeline.py`
- `src/securemail/adapters/ml/baselines.py`
- `src/securemail/adapters/ml/isolation_forest.py`

## Test evidence

- `tests/test_evaluate_ml.py`
- `tests/unit/test_ml_evaluation.py`
- `tests/unit/test_advisory_pipeline.py`
