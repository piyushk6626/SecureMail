"""FastAPI routers."""

from securemail.api.routers.analyses import router as analyses_router
from securemail.api.routers.reports import router as reports_router

__all__ = ["analyses_router", "reports_router"]
