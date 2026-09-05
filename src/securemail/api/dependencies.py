"""Shared FastAPI dependencies for the report and capture-analysis APIs."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, cast

from fastapi import Depends, Request

from securemail.application.render_report import RenderHtmlFn, RenderPdfFn
from securemail.application.report_queries import CanonicalizeFn
from securemail.domain.jobs.models import MAX_CAPTURE_BYTES
from securemail.ports.jobs import AnalysisJobStore
from securemail.ports.persistence import ReportRepository

DigestFn = Callable[[bytes], str]


@dataclass(frozen=True)
class ApiDependencies:
    report_repository: ReportRepository
    canonicalize: CanonicalizeFn
    job_store: AnalysisJobStore | None = None
    max_capture_bytes: int = MAX_CAPTURE_BYTES
    digest: DigestFn | None = None
    render_html: RenderHtmlFn | None = None
    render_pdf: RenderPdfFn | None = None


def get_api_dependencies(request: Request) -> ApiDependencies:
    return cast(ApiDependencies, request.app.state.securemail_dependencies)


ApiDependenciesDep = Annotated[ApiDependencies, Depends(get_api_dependencies)]
