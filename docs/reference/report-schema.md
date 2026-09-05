---
status: current
audience: user
authoritative_for: securemail.report/v1 JSON envelope
last_verified: 2026-09-06
---

# Report schema

JSON is authoritative. HTML and PDF are presentations of the **same
in-memory** `CanonicalReport`. They are never assembled independently from raw
evidence.

- Schema id: `securemail.report/v1`
- Models: [`src/securemail/domain/reports/schema.py`](../../src/securemail/domain/reports/schema.py)
- Generated JSON Schema snapshot:
  [`canonical_report.schema.json`](../../src/securemail/domain/reports/canonical_report.schema.json)

`securemail analyze` does **not** emit this envelope. Assembly is
[`assemble_report`](../../src/securemail/application/assemble_report.py)
(dashboard worker) or a hand-authored golden for `securemail report`.

## Envelope

```text
CanonicalReport
  schema_version: "securemail.report/v1"
  manifest: ReportManifest
  evidence: EvidenceDocument          # the v2 analyze envelope, unmodified
  limitations: CaptureLimitations
  stage_errors: StageError[]          # empty when analysis completed
  suppressed_findings: Finding[]
  exceptions: str[]
  advisory: { present, items[] }      # filled by report --advisory or the worker
  analyst_conclusions: { present, notes[] }
```

Unavailable provenance fields stay labeled. They are not invented.

Validators require `manifest` digests and posture headline to match
`evidence.run_identity` and `evidence.posture`, and `limitations` counts to
match flows, handshakes, coverage, and preflight.

## `ReportManifest`

| Field | Notes |
|---|---|
| `generated_at` | RFC 3339 UTC |
| `case_id` / `capture_id` / `analysis_run_id` | Optional; max 160 chars |
| `source_capture_sha256` | Must equal `evidence.run_identity.capture_sha256` |
| `working_copy_sha256` | Required only when `working_copy_availability` is `present`. CLI path today: `unavailable` |
| `source_records` | `case` / `capture` / `analysis_run` identifiers |
| `artifact_hashes` | Named hashes when present |
| `renderer` | HTML/PDF pins (see below) |
| `signature` | Always `availability: unavailable` (no RFC 3161 in this build) |
| `posture_summary` | Copied from `evidence.posture`; not independently scored |
| `timezone` | Always `UTC` |
| `configuration_digest` / `analyzer_bundle_digest` / `policy_profile` / `policy_pack_version` / `trust_store_digest` | Must match run identity |
| `os_container` | Optional; availability-gated |
| `dependency_versions` | e.g. jinja2, weasyprint |

The report’s own RFC 8785 digest is **not** stored inside the object. `securemail
report` writes it beside JSON as `report.json.sha256`.

### `RendererManifest`

| Field | Live value |
|---|---|
| `html_renderer` | `securemail.html/v1` |
| `pdf_renderer` | `weasyprint` |
| `pdf_renderer_version` | WeasyPrint version string (69.0 in this pin) |
| `template_name` | `report.html.j2` |
| `template_sha256` | SHA-256 of the template bytes |
| `fonts` | Bundled Noto Sans / Noto Sans Mono with per-file SHA-256 |

### `PostureSummary`

`assessment_state`, `risk_score`, `finding_count`, `unknown_count`,
`not_observable_count`. Formula owned by [scoring](../user-guide/scoring-and-coverage.md).

## `CaptureLimitations`

| Field | Meaning |
|---|---|
| `truncated_packets_present` | Must match preflight |
| `incomplete_flow_count` / `conflicting_flow_count` | Counted from `evidence.flows` |
| `not_observable_certificate_count` | Handshakes whose `server_certificate_state` is `not_observable` |
| `unknown_check_count` / `not_observable_check_count` | Must match coverage overall |
| `notes` | Human-readable visibility notes (max 32) |

These counts must not be read as a pass.

## Advisory and analyst sections

`AdvisoryItem` has only `code` and `reason` (max 64 / 1000).

**Known limitation:** mapping from `AnomalyResult` drops detector name,
endpoint id, score, and contribution metadata. See
[known limitations](../status/known-limitations.md).

`present=false` forbids items; `present=true` requires at least one item.
A capture with no history often emits `ADVISORY_NONE` or
`ADVISORY_INSUFFICIENT_HISTORY` rather than an empty section.

Analyst notes use the same present/items discipline. The live dashboard does
not persist analyst notes.

## Artifacts (`securemail report`)

| File | Contents |
|---|---|
| `report.json` | RFC 8785 canonical bytes (compact, not pretty-printed) |
| `report.json.sha256` | SHA-256 of those bytes, GNU `sha256sum` line |
| `report.html` | Self-contained HTML (inlined CSS, SVG, `data:` fonts) |
| `report.pdf` | WeasyPrint rendering of that exact HTML string |

`analyze` and `score` still write pretty, sorted JSON. Report JSON is JCS
because it is the integrity object.

PDF needs the `reports` extra. JSON and HTML do not import WeasyPrint at
module load.

Frontend TypeScript types are generated from the JSON Schema snapshot:

```bash
npm --prefix frontend run generate:types
```

Do not hand-edit `frontend/src/types/canonical_report.generated.ts`.

## Related pages

- [Evidence schema](evidence-schema.md)
- [CLI `report`](cli.md)
- [Report development](../development/report-development.md)
- [Report rendering security](../security/report-rendering-security.md)

## Implementation anchors

- `src/securemail/domain/reports/schema.py`
- `src/securemail/domain/reports/canonical_report.schema.json`
- `src/securemail/application/assemble_report.py`
- `src/securemail/application/render_report.py`

## Test evidence

- `tests/unit/test_report_schema.py`
- `tests/unit/test_canonical_json.py`
- `tests/test_report_fixtures.py`
- `tests/fixtures/reports/golden_report.json`
