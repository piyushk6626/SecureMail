---
status: current
audience: operator
authoritative_for: CLI exit codes and analysis exception types
last_verified: 2026-09-06
---

# Exit codes and errors

Typer missing-path checks exit **2**. Command bodies that catch analysis or
validation failures print the message on stderr and exit **1**. Success is **0**.

## Process exits

| Exit | When |
|---|---|
| `0` | Command completed. `evaluate-ml` also requires `gates.all_passed`. |
| `1` | Analysis, capture, JSON, schema, oversize, renderer, or ML-gate failure. |
| `2` | Typer rejected the argv: missing path (`exists=True`), unreadable file, or unknown `--policy-profile` enum value. |

Unknown `--policy-profile` is a Typer enum parse failure (exit 2), not an
`AnalysisError`.

## `analyze`

Caught in [`api/cli/main.py`](../../src/securemail/api/cli/main.py)
`register_analyze`:

| Exception | Typical cause | Exit |
|---|---|---|
| `InvalidCaptureError` | Not PCAP/PCAPNG magic | 1 |
| `AnalysisError` | Analyzer, pack load, or historical evaluation without `capture_start_time` | 1 |
| `FileNotFoundError` / `OSError` | I/O after Typer’s path check | 1 |
| `ValueError` | Invalid `--analysis-time` | 1 |

`InvalidCaptureError` subclasses `AnalysisError`.

## `score`

[`api/cli/commands/score.py`](../../src/securemail/api/cli/commands/score.py)
exits 1 on `OSError`, `UnicodeDecodeError`, `json.JSONDecodeError`,
`ValidationError`, or `ValueError` (including the 8 MiB input cap). A missing
path exits 2 (Typer `exists=True`).

## `report`

[`api/cli/commands/report.py`](../../src/securemail/api/cli/commands/report.py)
exits 1 on `OSError`, `ReportQueryError`, `ReportError`, `AdvisoryPipelineError`,
or `ValueError` (invalid `--format`, oversize, schema). Missing HTML/PDF bytes
from the renderer also exit 1. A missing path exits 2.

## `evaluate-ml`

[`api/cli/commands/evaluate_ml.py`](../../src/securemail/api/cli/commands/evaluate_ml.py)
prints the evaluation JSON, then exits 1 if `report.gates.all_passed` is false.
Load/validation/`AdvisoryPipelineError` also exit 1. A missing cohort directory
exits 2.

## HTTP errors

HTTP status codes are owned by the [API reference](api.md). They are not CLI
exits. Capture analysis that is not configured returns **503**. Health is
liveness only (`{"status":"ok"}`) and does not fail when Docker or the worker
is down.

## Related pages

- [CLI](cli.md)
- [API](api.md)
- [Limits](limits.md)

## Implementation anchors

- `src/securemail/api/cli/main.py`
- `src/securemail/api/cli/commands/score.py`
- `src/securemail/api/cli/commands/report.py`
- `src/securemail/api/cli/commands/evaluate_ml.py`
- `src/securemail/application/run_analysis.py` (`AnalysisError`, `InvalidCaptureError`)

## Test evidence

- `tests/test_scoring_fixtures.py` (invalid score input)
- `tests/test_report_fixtures.py` (invalid report input)
- `tests/test_evaluate_ml.py`
