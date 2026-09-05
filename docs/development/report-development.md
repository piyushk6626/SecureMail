---
status: current
audience: contributor
authoritative_for: canonical report schema, template, and renderer changes
last_verified: 2026-09-06
---

# Report development

JSON is authoritative. Change the Pydantic models in
[`schema.py`](../../src/securemail/domain/reports/schema.py) first, then
regenerate the JSON Schema snapshot consumed by frontend types.

```bash
# after model changes, refresh schema snapshot in the same change
# then:
npm --prefix frontend run generate:types
```

One HTML template:
[`report.html.j2`](../../src/securemail/adapters/reports/templates/report.html.j2).
Jinja autoescape stays on. There is no `|safe`. The `forensic_text` filter
turns C0/C1 controls and Unicode bidi overrides into visible `\uXXXX`
sequences; Jinja then HTML-escapes the result. Canonical JSON keeps the
original bytes.

Fonts are bundled under `adapters/reports/fonts/` (Noto Sans / Noto Sans Mono,
SIL OFL) and embedded as `data:` URIs. The PDF fetcher allows only `data:`
URLs; HTTP, file, and DNS fetches are fatal. Do not `brew install weasyprint`.

Render path:

```text
CanonicalReport.model_validate
  → model_dump(mode="json") once
  → RFC 8785 bytes + SHA-256
  → Jinja2 HTML (same dump)
  → WeasyPrint PDF (same HTML string)
```

Four labeled regions are mandatory: observed facts, deterministic conclusions,
advisory/ML, analyst notes. Unknown and not-observable coverage must be drawn
and counted.

Golden: `tests/fixtures/reports/golden_report.json` covers every
`EvidenceState`, a TLS 1.3 `not_observable` certificate, truncated/incomplete/
conflicting flows, and a hostile SMTP banner (`<script>`, NUL/BEL, U+202E).

## Related pages

- [Report schema](../reference/report-schema.md)
- [Report rendering security](../security/report-rendering-security.md)
- [Golden updates](golden-updates.md)
- [Frontend development](frontend-development.md)

## Implementation anchors

- `src/securemail/application/render_report.py`
- `src/securemail/adapters/reports/html_renderer.py`
- `src/securemail/adapters/reports/pdf_renderer.py`
- `src/securemail/adapters/reports/canonical_json.py`

## Test evidence

- `tests/unit/test_html_renderer.py`
- `tests/unit/test_pdf_renderer.py`
- `tests/unit/test_report_schema.py`
- `tests/test_report_fixtures.py`
