# Advisory ML (Step 10)

SecureMail’s ML stage is **advisory only**. It scores endpoint-window deviations
from a site/role baseline after deterministic policy evaluation. It never
suppresses, downgrades, or rewrites a `Finding`.

## What it is not

It is not cryptographic risk classification and not a replacement for Step 7
rule packs. “TLS 1.0 is deprecated” remains a deterministic finding. The ML
output is an **anomaly level** with an evidence-linked reason string.

## Detectors

1. **Baseline** (always on when advisory runs): per-endpoint median/MAD and
   Page-Hinkley on rate features, plus peer-group categorical rarity for issuer
   and dominant TLS version.
2. **Isolation Forest** (challenger): sklearn Isolation Forest on the same
   windows, using rates, past-only robust residuals, and rarity. It is in the
   tree only because a committed harness showed it beating the baseline on the
   locked synthetic cohort.

Both adapters implement `ports.ml.AnomalyScorer`. Orchestration lives in
[`application/advisory_pipeline.py`](../src/securemail/application/advisory_pipeline.py).
Canonical records are `AnomalyResult` and `EndpointWindow` under `domain/ml/`.

## Evaluation contract

Frozen in `domain/ml/evaluation.py` before the Isolation Forest adapter was
written:

| Gate | Value | Why |
|---|---|---|
| Detection delay | ≤ 2 daily windows | one missed daily job plus the next |
| Top-K | 5 | small analyst review budget |
| Baseline precision@5 floor | 0.60 | 3/5 true endpoints in that budget |
| Isolation Forest lift | +0.10 absolute | material, not a 0.01 benchmark win |

The locked cohort is
[`tests/support/synthetic_cohorts/cohort_seeded_v1/`](../tests/support/synthetic_cohorts/cohort_seeded_v1/)
(seed `20260904`). Development seed `20260101` is held out. History, rarity
tables, and Isolation Forest fits use **past windows only**.

Proof command:

```bash
uv sync --extra ml --extra dev
uv run securemail evaluate-ml tests/support/synthetic_cohorts/cohort_seeded_v1/
```

The command prints detection delay, precision@5, alerts per 1,000 endpoint-days,
and gate booleans. It exits 1 if any gate fails.

## `--advisory`

Off by default on `securemail report`. When set, the pipeline scores the report’s
`evidence` object and fills the existing Advisory / ML section. Deterministic
findings stay byte-identical. A single capture usually has no trailing history,
so the section may contain `ADVISORY_NONE` rather than invented anomalies.

The dashboard worker uses local endpoint-window history. Until 14 windows exist,
it publishes `ADVISORY_INSUFFICIENT_HISTORY` instead of `ADVISORY_NONE`. Isolation
Forest stays silent until 40 windows. See [dashboard.md](dashboard.md).

## Reasons

Every shipped anomaly cites at least one canonical evidence field
(`handshake.version.selected`, `handshake.established`, `certificate.issuer`,
…). Generic “anomaly detected” strings are a test failure.
