"""FastAPI application factory."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .core.config import get_settings
from .core.database import close_db, init_db
from .core.logging import setup_logging
from .core.redis import close_redis
from .middleware.csrf import CSRFMiddleware
from .middleware.security_headers import SecurityHeadersMiddleware
from .routers import health, reports, scans


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup and shutdown lifecycle."""
    settings = get_settings()
    setup_logging(json_output=settings.is_prod)

    # In dev/test, auto-create tables
    if settings.is_dev or settings.is_test:
        await init_db()

    yield

    await close_redis()
    await close_db()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="FootprintX API",
        description="Privacy-first digital footprint auditing API",
        version="1.0.0",
        docs_url="/docs" if settings.is_dev else None,
        redoc_url=None,
        lifespan=lifespan,
    )

    # CORS — only allow the web origin
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.web_origin],
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type", "X-Requested-With"],
        expose_headers=[],
    )

    # Security headers
    app.add_middleware(SecurityHeadersMiddleware)

    # CSRF protection
    app.add_middleware(CSRFMiddleware)

    # Routers
    app.include_router(health.router)
    app.include_router(scans.router)
    app.include_router(reports.router)

    return app


app = create_app()
