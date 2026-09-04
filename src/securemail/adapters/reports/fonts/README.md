# Bundled report fonts

Static Latin TTF subsets of **Noto Sans** and **Noto Sans Mono**, licensed under
the SIL Open Font License 1.1 (`OFL.txt`).

| File | Family | Weight |
|---|---|---|
| `NotoSans-Regular.ttf` | Noto Sans | 400 |
| `NotoSans-Bold.ttf` | Noto Sans | 700 |
| `NotoSansMono-Regular.ttf` | Noto Sans Mono | 400 |

HTML and PDF renderers embed these files as `data:` URIs. They must not fall
back to system fonts. SHA-256 of each file is pinned in the golden report
manifest and `tests/fixtures/reports/provenance.json`.
