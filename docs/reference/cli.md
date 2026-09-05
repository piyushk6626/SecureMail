---
status: current
audience: user
authoritative_for: CLI commands, options, and examples
last_verified: 2026-09-06
---

# CLI reference

Entry point: `securemail = "securemail.api.cli.main:main"` in
[`pyproject.toml`](../../pyproject.toml). `main()` loads the Typer app from
[`bootstrap.create_cli()`](../../src/securemail/bootstrap.py).

Registered commands: `analyze`, `score`, `report`, `evaluate-ml`.
`api/cli/commands/analyze.py` is an unused Step 0 stub; live `analyze` is
`register_analyze` in [`api/cli/main.py`](../../src/securemail/api/cli/main.py).

```bash
uv run securemail analyze <capture.pcap|capture.pcapng> --out <path.json>
uv run securemail score <findings.json>
uv run securemail report <report.json> --format json,html,pdf --out <directory>
uv run securemail evaluate-ml <cohort_directory>
```

`analyze` writes a `securemail.evidence/v2` `EvidenceDocument`. `report` reads a
`securemail.report/v1` `CanonicalReport`. There is **no** CLI command that
assembles analyze output into a report envelope. That assembly runs in the
dashboard worker via
[`assemble_report`](../../src/securemail/application/assemble_report.py).

## `analyze`

| Option | Default | Notes |
|---|---|---|
| `capture` (argument) | required | Existing readable file. Typer rejects missing paths (exit 2). |
| `--out` | required | JSON output path. Parent directories are created. |
| `--analysis-time` | now (UTC) | RFC 3339 instant for `valid_at_analysis_time` and IETF/NIST evaluation clock. |
| `--expiry-warning-days` | `30` (minimum 1) | Window for `expires_within_warning_window`. |
| `--expected-hostname` | observed SNI | RFC 9525 reference identity; sets `reference_identity_source=configured`. |
| `--policy-profile` | `ietf_current` | `ietf_current`, `nist_federal`, or `historical_at_capture`. Unknown values exit 2. |

Behavior:

- Validates PCAP/PCAPNG magic, then SHA-256 hashes the original file.
- Writes pretty JSON: `indent=2`, `sort_keys=True`, `ensure_ascii=False`, trailing newline.
- Writes extracted certificate DER to `<out-parent>/certificates/<sha256>.der`.
- `historical_at_capture` without `capture_start_time` is an `AnalysisError` (exit 1).

```bash
uv run securemail analyze \
  tests/fixtures/tls13_psk_only_resumption/capture.pcapng \
  --policy-profile ietf_current \
  --analysis-time 2026-09-04T12:00:00Z \
  --out out/policy.json
```

## `score`

Reads `securemail.score_request/v1` JSON (max 8 MiB) and writes a
`PostureAssessment` to stdout in the same pretty JSON style as analyze.

Invalid JSON, schema, or oversize input exits 1. A missing path exits 2.

```bash
uv run securemail score tests/fixtures/synthetic_findings/mixed_severity.json
```

Inventory labels are not inferred from a PCAP. They default to `unknown` unless
supplied in the score request.

## `report`

Reads `securemail.report/v1` JSON (max 8 MiB). `--out` is required.

| Option | Default | Notes |
|---|---|---|
| `--format` | `json,html,pdf` | Comma-separated `json`, `html`, `pdf`. |
| `--advisory` | off | Shadow-mode ML fills Advisory / ML; deterministic findings stay unchanged. |

Artifacts:

| File | Contents |
|---|---|
| `report.json` | RFC 8785 canonical bytes (compact) |
| `report.json.sha256` | GNU `sha256sum` line for those bytes |
| `report.html` | Self-contained HTML |
| `report.pdf` | WeasyPrint rendering of that HTML string |

PDF requires `uv sync --extra reports` and Pango. JSON/HTML do not import
WeasyPrint at module load.

```bash
uv run securemail report \
  tests/fixtures/reports/golden_report.json \
  --format json,html,pdf \
  --out out/
```

## `evaluate-ml`

Reads a seeded cohort directory (`manifest.json`, `labels.json`, `windows.json`)
and prints detection-delay / precision@K gates. Requires `uv sync --extra ml`.
Exits 1 when any gate fails.

```bash
uv run securemail evaluate-ml tests/support/synthetic_cohorts/cohort_seeded_v1/
```

## Related pages

- [Exit codes](exit-codes-and-errors.md)
- [Analyze captures](../user-guide/analyze-captures.md)
- [Generate reports](../user-guide/generate-reports.md)
- [First CLI analysis](../getting-started/first-cli-analysis.md)

## Implementation anchors

- `src/securemail/api/cli/main.py`
- `src/securemail/api/cli/commands/score.py`
- `src/securemail/api/cli/commands/report.py`
- `src/securemail/api/cli/commands/evaluate_ml.py`

## Test evidence

- `tests/test_empty_fixture.py`
- `tests/test_scoring_fixtures.py`
- `tests/test_report_fixtures.py`
- `tests/unit/test_advisory_pipeline.py`
