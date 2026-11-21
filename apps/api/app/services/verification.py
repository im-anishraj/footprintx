"""OTP and magic-link verification service."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.security import (
    constant_time_compare,
    generate_magic_token,
    generate_otp,
    hash_otp,
    hash_token,
)
from ..models.scan import VerificationChallenge


async def create_challenge(
    db: AsyncSession, scan_id: uuid.UUID
) -> Tuple[str, str]:
    """
    Create an OTP + magic-link challenge for a scan.
    Returns (otp_plaintext, magic_token_plaintext).
    """
    settings = get_settings()

    otp = generate_otp()
    magic_token = generate_magic_token()

    challenge = VerificationChallenge(
        scan_id=scan_id,
        code_hash=hash_otp(otp, settings.server_pepper),
        magic_token_hash=hash_token(magic_token),
        attempts=0,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    db.add(challenge)
    await db.flush()

    return otp, magic_token


async def verify_otp(
    db: AsyncSession,
    scan_id: uuid.UUID,
    code: str,
) -> bool:
    """
    Verify an OTP code. Returns True on success.
    Increments attempt counter. Single-use: marks consumed on success.
    Max 5 attempts per challenge.
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)

    result = await db.execute(
        select(VerificationChallenge)
        .where(VerificationChallenge.scan_id == scan_id)
        .where(VerificationChallenge.consumed_at.is_(None))
        .where(VerificationChallenge.expires_at > now)
        .order_by(VerificationChallenge.expires_at.desc())
    )
    challenge = result.scalar_one_or_none()

    if challenge is None:
        return False

    if challenge.attempts >= 5:
        return False

    challenge.attempts += 1

    expected_hash = hash_otp(code, settings.server_pepper)
    if constant_time_compare(challenge.code_hash, expected_hash):
        challenge.consumed_at = now
        await db.flush()
        return True

    await db.flush()
    return False


async def verify_magic_token(
    db: AsyncSession,
    scan_id: uuid.UUID,
    token: str,
) -> bool:
    """
    Verify a magic-link token. Returns True on success.
    Single-use: marks consumed on success.
    """
    now = datetime.now(timezone.utc)
    token_hash = hash_token(token)

    result = await db.execute(
        select(VerificationChallenge)
        .where(VerificationChallenge.scan_id == scan_id)
        .where(VerificationChallenge.consumed_at.is_(None))
        .where(VerificationChallenge.expires_at > now)
        .order_by(VerificationChallenge.expires_at.desc())
    )
    challenge = result.scalar_one_or_none()

    if challenge is None:
        return False

    if constant_time_compare(challenge.magic_token_hash, token_hash):
        challenge.consumed_at = now
        await db.flush()
        return True

    return False
