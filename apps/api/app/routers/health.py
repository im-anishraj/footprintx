"""Health and modules endpoints."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..core.logging import get_logger
from ..services.scan_service import get_enabled_services

logger = get_logger("health")
router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check() -> JSONResponse:
    """Basic health check."""
    return JSONResponse(
        status_code=200,
        content={"status": "healthy", "service": "footprintx-api"},
    )


@router.get("/v1/modules")
async def list_modules() -> JSONResponse:
    """Public module list with health state. No emails or PII."""
    services = get_enabled_services()
    modules = []
    for svc in services:
        modules.append({
            "id": svc["id"],
            "name": svc["name"],
            "category": svc["category"],
            "enabled": svc.get("enabled", False),
            "health": "healthy",  # TODO: check canary Redis state
        })
    return JSONResponse(
        status_code=200,
        content={"modules": modules, "total": len(modules)},
    )
