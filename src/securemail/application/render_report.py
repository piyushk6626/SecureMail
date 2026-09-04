"""Assemble report artifacts from one in-memory canonical object."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from securemail.domain.reports.schema import CanonicalReport

ReportFormat = Literal["json", "html", "pdf"]
ALLOWED_REPORT_FORMATS: frozenset[str] = frozenset({"json", "html", "pdf"})

CanonicalizeFn = Callable[[Mapping[str, Any]], bytes]
RenderHtmlFn = Callable[[Mapping[str, Any]], str]
RenderPdfFn = Callable[[str], bytes]


class ReportError(Exception):
    """Raised when a report cannot be validated or rendered."""


class RenderedReport(BaseModel):
    """Bytes/strings derived from one `payload` object."""

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    payload: dict[str, Any]
    json_bytes: bytes
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    html: str | None = None
    pdf: bytes | None = None


def parse_report_formats(raw: str) -> tuple[ReportFormat, ...]:
    """Parse `--format json,html,pdf` into a de-duplicated ordered tuple."""

    tokens = [item.strip().lower() for item in raw.split(",") if item.strip()]
    if not tokens:
        raise ReportError("at least one report format is required")
    seen: set[str] = set()
    ordered: list[ReportFormat] = []
    for token in tokens:
        if token in seen:
            continue
        if token == "json":
            ordered.append("json")
        elif token == "html":
            ordered.append("html")
        elif token == "pdf":
            ordered.append("pdf")
        else:
            raise ReportError(f"unsupported report format: {token}")
        seen.add(token)
    return tuple(ordered)


def render_report(
    report: CanonicalReport,
    formats: Sequence[str],
    *,
    canonicalize: CanonicalizeFn,
    digest: Callable[[bytes], str],
    render_html: RenderHtmlFn,
    render_pdf: RenderPdfFn,
) -> RenderedReport:
    """Validate once, dump once, then derive every requested artifact from that dump."""

    requested = set(formats)
    unknown = requested - ALLOWED_REPORT_FORMATS
    if unknown:
        raise ReportError(f"unsupported report format: {sorted(unknown)[0]}")
    if not requested:
        raise ReportError("at least one report format is required")

    payload = report.model_dump(mode="json")
    json_bytes = canonicalize(payload)
    sha256 = digest(json_bytes)

    html: str | None = None
    pdf: bytes | None = None
    needs_html = "html" in requested or "pdf" in requested
    if needs_html:
        html = render_html(payload)
    if "pdf" in requested:
        if html is None:
            raise ReportError("PDF rendering requires HTML derived from the same object")
        pdf = render_pdf(html)
    return RenderedReport(payload=payload, json_bytes=json_bytes, sha256=sha256, html=html, pdf=pdf)
