"""CSRF protection middleware."""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..core.config import get_settings

# State-changing methods that require CSRF protection
_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Header required for state-changing requests
CSRF_HEADER = "X-Requested-With"


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF protection via custom header requirement.
    State-changing requests must include X-Requested-With header.
    Combined with strict CORS, this prevents cross-origin attacks.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        settings = get_settings()

        if request.method in _UNSAFE_METHODS:
            # Health check is exempt
            if request.url.path in ("/health", "/docs", "/openapi.json"):
                return await call_next(request)

            # Check for CSRF header
            if CSRF_HEADER not in request.headers:
                return JSONResponse(
                    status_code=403,
                    content={
                        "type": "about:blank",
                        "title": "CSRF validation failed",
                        "status": 403,
                        "detail": f"Missing required header: {CSRF_HEADER}",
                    },
                    media_type="application/problem+json",
                )

        return await call_next(request)
