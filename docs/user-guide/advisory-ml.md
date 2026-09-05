---
status: current
audience: user
authoritative_for: advisory ML behavior, history thresholds, and Finding isolation
last_verified: 2026-09-06
---

# Advisory ML

SecureMail’s ML stage is **advisory only**. It scores endpoint-window
deviations from a site/role baseline **after** deterministic policy
evaluation. It never suppresses, downgrades, rewrites, gates, or merges into
a `Finding`. `AnomalyResult` is a separate record type.

It is not cryptographic risk classification and not a replacement for YAML
rule packs. “TLS 1.0 is deprecated” remains a deterministic finding. The ML
output is an anomaly level with an evidence-linked reason string. Generic
“anomaly detected” strings are a test failure.

## Detectors

1. **Baseline** (always considered when advisory runs): per-endpoint
   median/MAD and Page-Hinkley on rate features, plus peer-group categorical
   rareness for `issuer_id` and `dominant_tls_version`.
2. **Isolation Forest** (challenger): sklearn Isolation Forest on the same
   windows, using rates, past-only robust residuals, and rarity. It is in the
   tree only because a committed harness showed it beating the baseline on the
   locked synthetic cohort by the frozen margin. Do not add a second model
   until that gate is rewritten and passed.

Both adapters implement `ports.ml.AnomalyScorer`. Orchestration:
`application/advisory_pipeline.py`.

History, rarity tables, and Isolation Forest fits use **past windows only**.
Issuers are stored as opaque `iss_<12 hex>` hashes, not raw distinguished
names.

## History thresholds (dashboard worker)

The worker persists derived windows in `{data_root}/ml_history/windows.jsonl`
(max 512, oldest dropped first). Thresholds:

| Local endpoint-windows | Advisory section |
|---|---|
| fewer than **14** | `ADVISORY_INSUFFICIENT_HISTORY` only. Never `ADVISORY_NONE`. Baseline and Isolation Forest are not treated as a clean bill of health. |
| **14–39** | Baseline may score. Isolation Forest still contributes `ADVISORY_INSUFFICIENT_HISTORY`. |
| **40 or more** | Both detectors may score. `ADVISORY_NONE` is allowed when nothing is above threshold. |

`ADVISORY_NONE` reason text states that scoring ran and no endpoint-window
deviation met the review threshold, and that deterministic findings are
unchanged.

A fresh data root after one upload therefore shows insufficient history, not
“no anomaly found.”

## CLI `--advisory`

Off by default on `securemail report`. When set, the pipeline scores **that
report’s evidence only** (no persisted history). A single capture usually
yields `ADVISORY_NONE` rather than invented anomalies.

```bash
uv run securemail report tests/fixtures/reports/golden_report.json \
  --advisory --format json --out out/
```

Requires `uv sync --extra ml` for Isolation Forest. Baseline code does not
import sklearn.

## Evaluation harness

Not an analyst day-to-day command. Frozen gates in `domain/ml/evaluation.py`
before the Isolation Forest adapter was written:

| Gate | Value |
|---|---|
| Detection delay | ≤ 2 daily windows |
| Top-K | 5 |
| Baseline precision@5 floor | 0.60 |
| Isolation Forest lift | +0.10 absolute |

```bash
uv sync --extra ml --extra dev
uv run securemail evaluate-ml tests/support/synthetic_cohorts/cohort_seeded_v1/
```

Prints detection delay, precision@5, alerts per 1,000 endpoint-days, and gate
booleans. Exit 1 if any gate fails. Locked cohort seed `20260904`. Development
seed `20260101` is held out.

## Advisory codes you may see

| Code | Typical driver |
|---|---|
| `ADVISORY_INSUFFICIENT_HISTORY` | Fewer than 14 windows, or Isolation Forest still warming (14–39). |
| `ADVISORY_NONE` | Scoring ran; nothing above threshold (CLI, or worker with ≥ 40 windows). |
| `ADVISORY_TLS_VERSION_SHIFT` | TLS version share / dominant version. |
| `ADVISORY_HANDSHAKE_FAILURE_RATE` | Unestablished handshakes. |
| `ADVISORY_ALERT_RATE` | TLS alerts. |
| `ADVISORY_STARTTLS_FALLBACK_RATE` | STARTTLS success/fallback rates. |
| `ADVISORY_FORWARD_SECRECY_RATE` | Forward-secrecy present rate. |
| `ADVISORY_CERTIFICATE_ISSUER` | Issuer id / certificate churn. |
| `ADVISORY_MULTIVARIATE_DEVIATION` | Isolation Forest multi-feature, or no mapped feature. |

Every shipped anomaly cites at least one canonical evidence field
(for example `handshake.version.selected`, `handshake.established`,
`certificate.issuer`).

Windows with `session_count < 10`, incomplete-reconstruction rate above 0.40,
or failed capture-quality gate are skipped (`insufficient_support` /
`capture_quality`), not scored as anomalies.

## Related pages

- [Dashboard workflows](dashboard-workflows.md)
- [Interpret findings](interpret-findings.md)
- [CLI reference](../reference/cli.md)
- [ML evaluation](../development/ml-evaluation.md)

## Implementation anchors

- `src/securemail/application/advisory_pipeline.py`
- `src/securemail/adapters/ml/baselines.py`
- `src/securemail/adapters/ml/isolation_forest.py`
- `src/securemail/domain/ml/evaluation.py`
- `src/securemail/adapters/persistence/ml_history_store.py`

## Test evidence

- `tests/unit/test_advisory_history.py`
- `tests/unit/test_advisory_pipeline.py`
- `tests/unit/test_ml_isolation_forest.py`
- `tests/unit/test_analysis_workflow.py`
