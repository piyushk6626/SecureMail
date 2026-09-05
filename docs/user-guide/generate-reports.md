---
status: current
audience: user
authoritative_for: CanonicalReport rendering and the missing CLI assemble path
last_verified: 2026-09-06
---

# Generate reports

JSON is authoritative. HTML and PDF are presentations of the **same
in-memory object**. They are never assembled independently from raw evidence.

Schema: `securemail.report/v1`. `securemail report` **reads** that envelope.
`securemail analyze` **writes** `securemail.evidence/v2`. There is **no** CLI
command that wraps an evidence document in a report. The dashboard worker
calls `assemble_report` after upload.

## Envelope

```text
CanonicalReport
  schema_version: "securemail.report/v1"
  manifest: ReportManifest
  evidence: EvidenceDocument          # v2 analyze envelope, unmodified
  limitations: CaptureLimitations
  stage_errors: StageError[]          # empty when analysis completed
  suppressed_findings: Finding[]
  exceptions: str[]
  advisory: { present, items[] }      # filled by report --advisory or the worker
  analyst_conclusions: { present, notes[] }
```

Unavailable provenance fields stay labeled (`unavailable`). They are not
invented. The report’s RFC 8785 digest is **not** stored inside the object;
the CLI writes it beside JSON as `report.json.sha256`.

Worker assembly copies `working_copy_sha256` from the capture hash and marks
working-copy availability `present`. Signature/timestamp metadata remains
`unavailable` (no RFC 3161 in this build).

Limitations notes may include truncated packets, incomplete/conflicting flow
counts, and not-observable TLS 1.3 certificates. Those counts are not passes.

## CLI render

Use a committed canonical report (or a dashboard-published
`{case_id}.report.json`):

```bash
uv sync --extra dev --extra reports --extra ml
uv run securemail report tests/fixtures/reports/golden_report.json \
  --format json,html,pdf --out out/
```

`--out` is required. `--format` is a comma-separated list of `json`, `html`,
and `pdf` (default: all three). Input is bounded at 8 MiB. Invalid JSON,
schema, unknown format, or oversize input exits 1. A missing path exits 2.

`--advisory` is off by default. When set, shadow-mode ML fills Advisory / ML
without changing deterministic findings. A single capture usually has no
trailing history, so the CLI path may emit `ADVISORY_NONE`. The dashboard
worker uses local window history instead; see [advisory ML](advisory-ml.md).

Artifacts:

| File | Contents |
|---|---|
| `report.json` | RFC 8785 canonical bytes (compact, not pretty-printed) |
| `report.json.sha256` | SHA-256 of those bytes, GNU `sha256sum` line |
| `report.html` | Self-contained HTML (inlined CSS, SVG, `data:` fonts) |
| `report.pdf` | WeasyPrint rendering of that exact HTML string |

`analyze` and `score` still write pretty, sorted JSON. Report JSON is JCS
because it is the integrity object.

PDF requires the `reports` extra (WeasyPrint 69.0) and Pango. JSON and HTML
do not import WeasyPrint at module load. On macOS, `DYLD_FALLBACK_LIBRARY_PATH`
must include `/opt/homebrew/lib`. Do not `brew install weasyprint`.

## Render path

```text
read JSON → CanonicalReport.model_validate
         → model_dump(mode="json") once
         → RFC 8785 bytes + SHA-256
         → Jinja2 HTML (same dump)
         → WeasyPrint PDF (same HTML string)
```

Jinja autoescape stays on. There is no `|safe`. A presentation-only
`forensic_text` filter makes C0/C1 controls and Unicode bidi overrides
visible; Jinja then HTML-escapes the result. Canonical JSON keeps original
bytes.

Fonts are bundled under `adapters/reports/fonts/` (Noto Sans / Noto Sans Mono,
SIL OFL) as `data:` URIs. The PDF fetcher allows only `data:` URLs; HTTP,
file, and DNS fetches are fatal.

HTML sections include cover and integrity hashes, the four analyst regions
(observed facts, deterministic conclusions, advisory/ML, analyst notes),
limitations, coverage denominators, prioritized findings, lineage, STARTTLS
steppers, handshake timelines, certificate chains, policy checks, and
provenance. Unknown and not-observable coverage are drawn and counted.

## Dashboard downloads

After a job `completed`, HTML and PDF are stored as job artifacts and also
rendered from catalog JSON for case downloads. Routes:
[API reference](../reference/api.md).

`POST /api/v1/reports/preview` accepts report JSON (max 8 MiB) for
browser-local preview. The React dropzone’s primary intake is PCAP/PCAPNG,
not that preview endpoint.

## Related pages

- [Analyze captures](analyze-captures.md)
- [Dashboard workflows](dashboard-workflows.md)
- [CLI reference](../reference/cli.md)
- [Report schema](../reference/report-schema.md)
- [Pango / PDF troubleshooting](../operations/troubleshooting.md)

## Implementation anchors

- `src/securemail/application/assemble_report.py`
- `src/securemail/application/render_report.py`
- `src/securemail/api/cli/commands/report.py`
- `src/securemail/adapters/reports/templates/report.html.j2`

## Test evidence

- `tests/test_report_fixtures.py`
- `tests/unit/test_canonical_json.py`
- `tests/unit/test_html_renderer.py`
- `tests/unit/test_pdf_renderer.py`
- `tests/fixtures/reports/golden_report.json`
