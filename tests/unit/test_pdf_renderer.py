"""PDF renderer consumes HTML and preserves finding codes."""

from __future__ import annotations

import hashlib
import json
from io import BytesIO

from pypdf import PdfReader
from tests.support.fixture_harness import load_golden_report, repo_root

from securemail.adapters.reports.html_renderer import font_resources, render_html
from securemail.adapters.reports.pdf_renderer import render_pdf, weasyprint_version
from securemail.domain.reports.schema import CanonicalReport


def _provenance() -> dict[str, object]:
    path = repo_root() / "tests" / "fixtures" / "reports" / "provenance.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _pdf_from_golden() -> bytes:
    report = CanonicalReport.model_validate(load_golden_report())
    html = render_html(report.model_dump(mode="json"))
    return render_pdf(html)


def test_weasyprint_and_fonts_match_provenance() -> None:
    provenance = _provenance()
    assert weasyprint_version() == provenance["weasyprint_version"]
    fonts = provenance["fonts"]
    assert isinstance(fonts, dict)
    bundled = {item.filename: item.sha256 for item in font_resources()}
    assert bundled == fonts
    font_dir = repo_root() / "src" / "securemail" / "adapters" / "reports" / "fonts"
    for filename, digest in fonts.items():
        raw = (font_dir / str(filename)).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest


def test_pdf_text_contains_finding_codes_and_page_range() -> None:
    pdf = _pdf_from_golden()
    reader = PdfReader(BytesIO(pdf))
    provenance = _provenance()
    page_count = len(reader.pages)
    assert (
        int(provenance["pdf_page_count_min"]) <= page_count <= int(provenance["pdf_page_count_max"])
    )
    text = "\n".join((page.extract_text() or "") for page in reader.pages)
    codes = provenance["finding_codes"]
    assert isinstance(codes, list)
    for code in codes:
        assert str(code) in text


def test_pdf_renderer_rejects_empty_html() -> None:
    from securemail.adapters.reports.pdf_renderer import PdfRenderError

    try:
        render_pdf("   ")
    except PdfRenderError:
        return
    raise AssertionError("empty HTML must fail closed")


def test_url_fetcher_denies_http() -> None:
    from weasyprint.urls import FatalURLFetchingError

    from securemail.adapters.reports.pdf_renderer import offline_url_fetcher

    try:
        offline_url_fetcher().fetch("https://example.invalid/font.ttf")
    except FatalURLFetchingError as exc:
        assert "denied" in str(exc)
        return
    raise AssertionError("HTTP fetch must be denied")
