# Reports (JSON, HTML, PDF)

`securemail report` turns one canonical report object into JSON, HTML, and PDF.
JSON is authoritative. HTML and PDF are presentations of the same in-memory
object. They are never assembled independently from raw evidence.

Schema: `securemail.report/v1`. Models live in
[`src/securemail/domain/reports/schema.py`](../src/securemail/domain/reports/schema.py).
The generated JSON Schema snapshot is
[`canonical_report.schema.json`](../src/securemail/domain/reports/canonical_report.schema.json).

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
  advisory: { present, items[] }      # empty until Step 10
  analyst_conclusions: { present, notes[] }
```

`ReportManifest` records case/capture/run identifiers when they exist, source
and working-copy hashes (working copy is `unavailable` on the CLI path today),
analyzer/policy/trust/configuration digests copied from `run_identity`, renderer
and bundled-font pins, and a posture headline that must match
`evidence.posture`. Signature/timestamp metadata is `unavailable` (no RFC 3161
in Step 9). The report’s own RFC 8785 digest is **not** stored inside the
object; it is written beside JSON as `report.json.sha256`.

Unavailable fields stay labeled. They are not invented.

## CLI

```bash
uv sync --extra dev --extra reports
uv run securemail report tests/fixtures/reports/golden_report.json \
  --format json,html,pdf --out out/
```

`--out` is required. `--format` is a comma-separated list of `json`, `html`,
and `pdf` (default: all three). Input is bounded at 8 MiB. Invalid JSON,
schema, unknown format, or oversize input exits 1. A missing path exits 2.

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
do not import WeasyPrint at module load.

## Render path

```text
read JSON → CanonicalReport.model_validate
         → model_dump(mode="json") once
         → RFC 8785 bytes + SHA-256
         → Jinja2 HTML (same dump)
         → WeasyPrint PDF (same HTML string)
```

Orchestration: [`application/render_report.py`](../src/securemail/application/render_report.py).
Adapters: [`canonical_json.py`](../src/securemail/adapters/reports/canonical_json.py),
[`html_renderer.py`](../src/securemail/adapters/reports/html_renderer.py),
[`pdf_renderer.py`](../src/securemail/adapters/reports/pdf_renderer.py).
The CLI is a thin wrapper; bootstrap injects the renderer callables.

## HTML design

One template,
[`report.html.j2`](../src/securemail/adapters/reports/templates/report.html.j2),
with Jinja autoescape forced on. There is no `|safe`. A presentation-only
`forensic_text` filter turns C0/C1 controls and Unicode bidi overrides into
visible `\uXXXX` sequences; Jinja then HTML-escapes the result. Canonical JSON
keeps the original bytes.

Sections: cover and integrity hashes, contents, four regions (observed facts,
deterministic conclusions, advisory/ML, analyst notes), limitations, coverage
denominators with stacked bars, prioritized findings with score-component bars,
capture→flow→session→TLS→finding lineage, STARTTLS/STLS steppers, handshake
timelines, certificate chains, evidence tables, policy checks, provenance.

Unknown and not-observable coverage are drawn and counted. They are never
implied as pass. Status uses labels (`VER` / `OBS` / `NOB` / …) as well as
color.

Fonts are bundled under
[`adapters/reports/fonts/`](../src/securemail/adapters/reports/fonts/)
(Noto Sans / Noto Sans Mono, SIL OFL) and embedded as `data:` URIs. The PDF
fetcher allows only `data:` URLs; HTTP, file, and DNS fetches are fatal.

## Fixtures and tests

Schema-first golden:

```text
tests/fixtures/reports/
  golden_report.json     # hand-reviewed CanonicalReport
  provenance.json        # JCS SHA-256, WeasyPrint, font and template hashes, page range
  assemble.py            # regenerates the golden from typed models
```

The golden covers every `EvidenceState`, a TLS 1.3 `not_observable` certificate,
truncated/incomplete/conflicting flows, and a hostile SMTP banner (`<script>`,
NUL/BEL, U+202E). Tests assert the banner is escaped in HTML, the pinned JCS
hash is stable, JSON Schema rejects a required-field mutation, and every
finding code appears in JSON, HTML, and extracted PDF text. PDF bytes are not
goldened; page count must stay in the provenance range (currently 8–14; the
checked-in WeasyPrint 69.0 render is 11 pages).

Proof:

```bash
uv run securemail report tests/fixtures/reports/golden_report.json \
  --format json,html,pdf --out out/
```
