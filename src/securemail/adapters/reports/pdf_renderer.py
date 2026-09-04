"""WeasyPrint PDF rendering of the exact HTML produced for the HTML artifact."""

from __future__ import annotations

from typing import Any


class PdfRenderError(ValueError):
    """Raised when PDF rendering fails or a required extra is missing."""


def weasyprint_version() -> str:
    try:
        import weasyprint  # type: ignore[import-untyped]
    except ImportError as exc:
        raise PdfRenderError(
            "PDF rendering requires the reports extra (uv sync --extra reports)"
        ) from exc
    version = getattr(weasyprint, "__version__", None)
    if not isinstance(version, str) or not version:
        raise PdfRenderError("WeasyPrint version is unavailable")
    return version


def offline_url_fetcher() -> Any:
    """Fetch only `data:` URIs already embedded in the HTML. HTTP/file/DNS are fatal."""

    from weasyprint.urls import FatalURLFetchingError, URLFetcher  # type: ignore[import-untyped]

    class OfflineFetcher(URLFetcher):  # type: ignore[misc]
        def fetch(self, url: str, headers: dict[str, str] | None = None) -> Any:
            if not url.startswith("data:"):
                raise FatalURLFetchingError(f"external resource fetch denied: {url}")
            return super().fetch(url, headers)

    return OfflineFetcher(allowed_protocols={"data"}, allow_redirects=False)


def render_pdf(html: str) -> bytes:
    """Render PDF bytes from the HTML string already produced for the HTML output."""

    if not html.strip():
        raise PdfRenderError("PDF renderer requires non-empty HTML")
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise PdfRenderError(
            "PDF rendering requires the reports extra (uv sync --extra reports)"
        ) from exc
    document = HTML(
        string=html,
        base_url="about:blank",
        url_fetcher=offline_url_fetcher(),
        media_type="print",
    ).render()
    pdf = document.write_pdf()
    if not isinstance(pdf, (bytes, bytearray)):
        raise PdfRenderError("WeasyPrint did not return PDF bytes")
    return bytes(pdf)
