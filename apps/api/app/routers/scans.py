"""Scan API endpoints — /v1/scans."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Cookie, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.database import get_db
from ..core.email import send_verification_email
from ..core.logging import get_logger
from ..core.redis import get_redis
from ..core.security import (
    create_session_token,
    hash_ip,
    verify_session_token,
)
from ..services.captcha import verify_captcha
from ..services.queue_service import enqueue_scan_job, get_scan_result
from ..services.rate_limiter import RateLimitExceeded, RateLimiter
from ..services.scan_service import (
    create_scan,
    delete_scan,
    email_hmac,
    get_results,
    get_scan,
    is_disposable_domain,
    mark_verified,
    normalise_email,
    store_results,
    validate_email,
)
from ..services.verification import create_challenge, verify_magic_token, verify_otp

logger = get_logger("scans_router")
router = APIRouter(prefix="/v1/scans", tags=["scans"])


# ── Pydantic models ─────────────────────────────────────────────

class ConsentBody(BaseModel):
    version: str
    accepted: bool


class CreateScanRequest(BaseModel):
    email: str = Field(..., max_length=254)
    consent: ConsentBody
    captcha_token: str = Field(..., min_length=1)


class VerifyRequest(BaseModel):
    code: Optional[str] = None
    token: Optional[str] = None


class ScanResponse(BaseModel):
    id: str
    state: str
    message: str


class ScanStatusResponse(BaseModel):
    id: str
    state: str
    modules_total: int
    modules_done: int
    modules_failed: int
    created_at: str
    expires_at: Optional[str] = None


# ── Helpers ──────────────────────────────────────────────────────

def _problem_json(status: int, title: str, detail: str) -> JSONResponse:
    """Return application/problem+json error."""
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


def _get_client_ip(request: Request) -> str:
    """Get client IP from request (handles proxies)."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


async def _get_session_scan_id(
    request: Request,
) -> Optional[str]:
    """Extract and verify scan_id from session cookie."""
    settings = get_settings()
    session_cookie = request.cookies.get("fpx_session")
    if not session_cookie:
        return None
    return verify_session_token(session_cookie, settings.session_secret)


async def _require_session(
    request: Request,
    scan_id: str,
) -> bool:
    """Verify session matches scan_id. Returns True if valid."""
    session_scan_id = await _get_session_scan_id(request)
    if session_scan_id is None:
        return False
    return session_scan_id == scan_id


# ── Endpoints ────────────────────────────────────────────────────

@router.post("", status_code=202)
async def create_scan_endpoint(
    body: CreateScanRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Create a new scan. Always returns 202 with identical body.
    Email sending happens in background task.
    """
    settings = get_settings()

    # Always return the same response structure and similar timing
    # to prevent email enumeration
    uniform_response = JSONResponse(
        status_code=202,
        content={
            "id": "",
            "state": "pending_verification",
            "message": "If this address can receive mail, we've sent a code.",
        },
    )

    # Validate email format
    normalised = normalise_email(body.email)
    is_valid, _ = validate_email(normalised)

    # Validate consent
    if not body.consent.accepted or body.consent.version != settings.consent_version:
        # Still return 202 to not leak info
        # Add small delay for timing consistency
        await asyncio.sleep(0.05 + (hash(normalised) % 100) / 1000)
        scan_id = str(uuid.uuid4())
        uniform_response = JSONResponse(
            status_code=202,
            content={
                "id": scan_id,
                "state": "pending_verification",
                "message": "If this address can receive mail, we've sent a code.",
            },
        )
        return uniform_response

    # Verify CAPTCHA (but don't reveal result to prevent enumeration)
    captcha_ok = await verify_captcha(body.captcha_token, _get_client_ip(request))

    client_ip = _get_client_ip(request)
    ip_hashed = hash_ip(client_ip)
    e_hmac = email_hmac(normalised)

    # Create scan regardless (for uniform response)
    scan = await create_scan(db, e_hmac, body.consent.version, client_ip)
    scan_id = str(scan.id)

    uniform_response = JSONResponse(
        status_code=202,
        content={
            "id": scan_id,
            "state": "pending_verification",
            "message": "If this address can receive mail, we've sent a code.",
        },
    )

    # Background: rate-check and send email
    # We do this in a background task so the response timing is uniform
    async def _background_send():
        try:
            if not is_valid or not captcha_ok:
                return

            redis = await get_redis()
            limiter = RateLimiter(redis)

            try:
                await limiter.check_ip_requests(ip_hashed)
                await limiter.check_email_scan(e_hmac)
                await limiter.check_email_otp(e_hmac)

                if is_disposable_domain(normalised):
                    await limiter.check_disposable_scan(e_hmac)
            except RateLimitExceeded:
                return

            # Create verification challenge
            otp, magic_token = await create_challenge(db, scan.id)
            await db.commit()

            # Build magic link URL
            magic_url = f"{settings.web_origin}/scan/{scan_id}?token={magic_token}"

            # Send email
            await send_verification_email(
                to_email=normalised,
                otp=otp,
                magic_link_url=magic_url,
                scan_id=scan_id,
            )
        except Exception:
            logger.exception("background_send_error", scan_id=scan_id)

    # Fire-and-forget background task
    asyncio.create_task(_background_send())

    # Small random delay for timing consistency
    await asyncio.sleep(0.05 + (hash(normalised) % 100) / 1000)

    return uniform_response


@router.post("/{scan_id}/verify")
async def verify_scan(
    scan_id: str,
    body: VerifyRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Verify OTP or magic-link token. Sets session cookie on success."""
    settings = get_settings()
    redis = await get_redis()
    limiter = RateLimiter(redis)

    client_ip = _get_client_ip(request)
    ip_hashed = hash_ip(client_ip)

    try:
        await limiter.check_ip_verify(ip_hashed)
    except RateLimitExceeded as e:
        return _problem_json(429, "Too many attempts", "Please try again later.")

    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        return _problem_json(404, "Not found", "Scan not found.")

    scan = await get_scan(db, scan_uuid)
    if scan is None or scan.state != "pending_verification":
        return _problem_json(404, "Not found", "Scan not found.")

    verified = False
    if body.code:
        verified = await verify_otp(db, scan_uuid, body.code)
    elif body.token:
        verified = await verify_magic_token(db, scan_uuid, body.token)
    else:
        return _problem_json(400, "Bad request", "Provide either code or token.")

    if not verified:
        return _problem_json(400, "Verification failed", "Invalid or expired code.")

    # Mark scan as verified and queue it
    await mark_verified(db, scan)

    # Enqueue scan job
    # Note: we need the email for scanning, but we don't store it in DB
    # In mock mode, the worker doesn't need the actual email
    await enqueue_scan_job(redis, scan_id, "")  # Email passed separately via secure channel

    # Create session
    session_token = create_session_token(scan_id, settings.session_secret)
    resp = JSONResponse(
        status_code=200,
        content={
            "id": scan_id,
            "state": "queued",
            "message": "Email verified. Scan queued.",
        },
    )
    resp.set_cookie(
        key="fpx_session",
        value=session_token,
        httponly=True,
        secure=settings.is_prod,
        samesite="lax",
        max_age=86400,
        path="/",
    )
    return resp


@router.get("/{scan_id}")
async def get_scan_status(
    scan_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Get scan state and progress. Requires session."""
    if not await _require_session(request, scan_id):
        return _problem_json(404, "Not found", "Scan not found.")

    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        return _problem_json(404, "Not found", "Scan not found.")

    scan = await get_scan(db, scan_uuid)
    if scan is None:
        return _problem_json(404, "Not found", "Scan not found.")

    if scan.state in ("expired", "deleted"):
        return _problem_json(410, "Gone", "This scan has expired or been deleted.")

    # Check if results are ready from queue
    if scan.state in ("queued", "running"):
        redis = await get_redis()
        result = await get_scan_result(redis, scan_id)
        if result is not None:
            # Store results in DB
            await store_results(db, scan_uuid, result)
            failed = result.get("modules_failed", 0)
            total = result.get("modules_total", 0)
            done = result.get("modules_done", 0)

            new_state = "completed"
            if failed > 0 and done > 0:
                new_state = "partial"
            elif failed == total:
                new_state = "failed"

            scan.state = new_state
            scan.modules_total = total
            scan.modules_done = done
            scan.modules_failed = failed
            await db.flush()

    return JSONResponse(
        status_code=200,
        content={
            "id": scan_id,
            "state": scan.state,
            "modules_total": scan.modules_total,
            "modules_done": scan.modules_done,
            "modules_failed": scan.modules_failed,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "expires_at": scan.expires_at.isoformat() if scan.expires_at else None,
        },
    )


@router.get("/{scan_id}/results")
async def get_scan_results(
    scan_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Get scan results. Requires session."""
    if not await _require_session(request, scan_id):
        return _problem_json(404, "Not found", "Scan not found.")

    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        return _problem_json(404, "Not found", "Scan not found.")

    scan = await get_scan(db, scan_uuid)
    if scan is None:
        return _problem_json(404, "Not found", "Scan not found.")

    if scan.state in ("expired", "deleted"):
        return _problem_json(410, "Gone", "This scan has expired or been deleted.")

    if scan.state in ("pending_verification", "queued", "running"):
        return _problem_json(409, "Not ready", "Scan is still in progress.")

    results = await get_results(db, scan_uuid)
    if results is None:
        return _problem_json(404, "Not found", "Results not available.")

    return JSONResponse(status_code=200, content=results)


@router.delete("/{scan_id}", status_code=204)
async def delete_scan_endpoint(
    scan_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Hard-delete scan and all associated data. Requires session."""
    if not await _require_session(request, scan_id):
        return _problem_json(404, "Not found", "Scan not found.")

    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        return _problem_json(404, "Not found", "Scan not found.")

    deleted = await delete_scan(db, scan_uuid)
    if not deleted:
        return _problem_json(404, "Not found", "Scan not found.")

    resp = Response(status_code=204)
    resp.delete_cookie("fpx_session", path="/")
    return resp
