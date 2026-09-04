"""FastAPI application factory and Uvicorn entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import RequestResponseEndpoint

from securemail.api.dependencies import ApiDependencies
from securemail.api.routers import reports_router

_APP: FastAPI | None = None


def build_app(
    dependencies: ApiDependencies,
    *,
    static_dir: Path | None = None,
) -> FastAPI:
    app = FastAPI(title="SecureMail API", version="1.0.0")
    app.state.securemail_dependencies = dependencies
    app.include_router(reports_router)

    @app.middleware("http")
    async def add_same_origin_security_headers(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'self'; object-src 'none'; "
            "frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    if static_dir is not None and static_dir.is_dir():
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="frontend")
    return app


def __getattr__(name: str) -> Any:
    """Expose ``app`` for Uvicorn without importing bootstrap at module load."""

    if name != "app":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    global _APP
    if _APP is None:
        from securemail.bootstrap import create_api

        _APP = create_api()
    return _APP
