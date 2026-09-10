"""FastAPI application factory and Uvicorn entry point."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi import FastAPI, Request, Response
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import RequestResponseEndpoint
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

from securemail.api.dependencies import ApiDependencies
from securemail.api.routers import analyses_router, reports_router

_APP: FastAPI | None = None


class SpaStaticFiles(StaticFiles):
    """Serve the SPA index for extensionless client routes."""

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code != 404 or not self.html:
                raise
            if PurePosixPath(path).suffix:
                raise
            return await super().get_response("index.html", scope)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    process: subprocess.Popen[bytes] | None = None
    if getattr(app.state, "start_worker", False):
        env = os.environ.copy()
        data_root = getattr(app.state, "data_root", None)
        report_root = getattr(app.state, "report_root", None)
        if data_root is not None:
            env["SECUREMAIL_DATA_ROOT"] = str(data_root)
        if report_root is not None:
            env["SECUREMAIL_REPORT_ROOT"] = str(report_root)
        if sys.platform == "darwin":
            homebrew_lib = "/opt/homebrew/lib"
            current = env.get("DYLD_FALLBACK_LIBRARY_PATH", "")
            parts = [item for item in current.split(":") if item]
            if homebrew_lib not in parts:
                env["DYLD_FALLBACK_LIBRARY_PATH"] = ":".join([homebrew_lib, *parts])
        process = subprocess.Popen(
            [sys.executable, "-m", "securemail.worker"],
            env=env,
        )
    try:
        yield
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()


def build_app(
    dependencies: ApiDependencies,
    *,
    static_dir: Path | None = None,
    start_worker: bool = False,
    data_root: Path | None = None,
    report_root: Path | None = None,
) -> FastAPI:
    app = FastAPI(title="SecureMail API", version="1.0.0", lifespan=_lifespan)
    app.state.securemail_dependencies = dependencies
    app.state.start_worker = start_worker
    app.state.data_root = data_root
    app.state.report_root = report_root
    app.include_router(reports_router)
    app.include_router(analyses_router)

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
        app.mount("/", SpaStaticFiles(directory=static_dir, html=True), name="frontend")
    return app


def __getattr__(name: str) -> Any:
    """Expose ``app`` for Uvicorn without importing bootstrap at module load."""

    if name != "app":
        raise AttributeError(f"module {__name__!r} has no attribute {name}")
    global _APP
    if _APP is None:
        from securemail.bootstrap import create_api

        configured = bool(
            os.environ.get("SECUREMAIL_DATA_ROOT") or os.environ.get("SECUREMAIL_REPORT_ROOT")
        )
        start_worker = os.environ.get("SECUREMAIL_START_WORKER", "1" if configured else "0") == "1"
        _APP = create_api(start_worker=start_worker)
    return _APP
