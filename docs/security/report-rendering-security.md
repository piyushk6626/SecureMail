---
status: current
audience: security
authoritative_for: HTML/PDF escaping, font embedding, and API security headers
last_verified: 2026-09-06
---

# Report rendering security

JSON is the integrity object (RFC 8785). HTML and PDF must not become a second
source of findings.

## HTML

- Single template `report.html.j2`.
- Jinja2 autoescape forced on. No `|safe`.
- `forensic_text` makes C0/C1 controls and Unicode bidi overrides visible as
  `\uXXXX`, then Jinja HTML-escapes the result.
- Hostile SMTP banners in the golden report (`<script>`, NUL/BEL, U+202E)
  must appear escaped in HTML and as text in extracted PDF.

The dashboard uses a parallel `forensic_text.ts` for UI strings.

## PDF

- WeasyPrint renders the **same HTML string**.
- Fonts are bundled under `adapters/reports/fonts/` and embedded as `data:`
  URIs. Never system fonts.
- PDF URL fetcher allows **only** `data:`. HTTP, file, and DNS fetches are
  fatal.

## API headers

All FastAPI responses set:

- `Cache-Control: no-store`
- `Content-Security-Policy` (`default-src 'self'`, `object-src 'none'`,
  `frame-ancestors 'none'`, `form-action 'self'`, `base-uri 'self'`)
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- `Referrer-Policy: no-referrer`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`

There is no authentication. Headers reduce incidental browser risk; they do
not replace an identity plane.

## Related pages

- [Report schema](../reference/report-schema.md)
- [Report development](../development/report-development.md)
- [API](../reference/api.md)

## Implementation anchors

- `src/securemail/adapters/reports/html_renderer.py`
- `src/securemail/adapters/reports/pdf_renderer.py`
- `src/securemail/api/main.py`
- `frontend/src/core/forensic_text.ts`

## Test evidence

- `tests/unit/test_html_renderer.py`
- `tests/unit/test_pdf_renderer.py`
- `frontend/src/core/forensic_text.test.ts`
