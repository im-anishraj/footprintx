"""Turnstile CAPTCHA verification."""
from __future__ import annotations

import httpx

from ..core.config import get_settings
from ..core.logging import get_logger

logger = get_logger("captcha")

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


async def verify_captcha(token: str, remote_ip: str | None = None) -> bool:
    """
    Verify a Cloudflare Turnstile CAPTCHA token.
    Returns True if valid, False otherwise.
    In test environment, always returns True.
    """
    settings = get_settings()

    if settings.is_test:
        return True

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            payload: dict[str, str] = {
                "secret": settings.turnstile_secret_key,
                "response": token,
            }
            if remote_ip:
                payload["remoteip"] = remote_ip

            resp = await client.post(TURNSTILE_VERIFY_URL, data=payload)
            resp.raise_for_status()
            data = resp.json()
            success = data.get("success", False)
            if not success:
                logger.warning("captcha_failed", error_codes=data.get("error-codes", []))
            return success
    except Exception:
        logger.exception("captcha_verification_error")
        # Fail open in dev, fail closed in prod
        return settings.is_dev
