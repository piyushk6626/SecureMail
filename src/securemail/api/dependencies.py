"""Shared FastAPI dependencies for the read-only report API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, cast

from fastapi import Depends, Request

from securemail.application.report_queries import CanonicalizeFn
from securemail.ports.persistence import ReportRepository


@dataclass(frozen=True)
class ApiDependencies:
    report_repository: ReportRepository
    canonicalize: CanonicalizeFn


def get_api_dependencies(request: Request) -> ApiDependencies:
    return cast(ApiDependencies, request.app.state.securemail_dependencies)


ApiDependenciesDep = Annotated[ApiDependencies, Depends(get_api_dependencies)]
