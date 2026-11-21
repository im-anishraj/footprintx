"""Report endpoints — PDF and Markdown generation."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.database import get_db
from ..core.security import verify_session_token
from ..services.report_service import (
    generate_markdown_report,
    generate_pdf_report,
    mask_email,
)
from ..services.scan_service import get_results, get_scan

router = APIRouter(prefix="/v1/scans", tags=["reports"])


def _problem_json(status: int, title: str, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "type": "about:blank",
            "title": title,
            "status": status,
            "detail": detail,
        },
        media_type="application/problem+json",
    )


@router.get("/{scan_id}/report")
async def get_report(
    scan_id: str,
    request: Request,
    format: str = Query("pdf", regex="^(pdf|md)$"),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Generate and return a report. Not stored."""
    settings = get_settings()
    session_cookie = request.cookies.get("fpx_session")
    if not session_cookie:
        return _problem_json(404, "Not found", "Scan not found.")

    session_scan_id = verify_session_token(session_cookie, settings.session_secret)
    if session_scan_id != scan_id:
        return _problem_json(404, "Not found", "Scan not found.")

    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        return _problem_json(404, "Not found", "Scan not found.")

    scan = await get_scan(db, scan_uuid)
    if scan is None or scan.state in ("expired", "deleted"):
        return _problem_json(410, "Gone", "This scan has expired or been deleted.")

    if scan.state in ("pending_verification", "queued", "running"):
        return _problem_json(409, "Not ready", "Scan is still in progress.")

    results = await get_results(db, scan_uuid)
    if results is None:
        return _problem_json(404, "Not found", "Results not available.")

    # Mask email in report (use the HMAC prefix as placeholder)
    masked = results.get("masked_email", "***@***.***")

    if format == "md":
        md = generate_markdown_report(results, masked)
        return Response(
            content=md,
            media_type="text/markdown",
            headers={
                "Content-Disposition": f'attachment; filename="footprintx-report-{scan_id[:8]}.md"'
            },
        )
    else:
        pdf = generate_pdf_report(results, masked)
        return Response(
            content=pdf,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="footprintx-report-{scan_id[:8]}.pdf"'
            },
        )
