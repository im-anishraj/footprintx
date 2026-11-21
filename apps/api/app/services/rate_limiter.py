"""Rate limiting using Redis sliding windows."""
from __future__ import annotations

import time
from typing import Optional

import redis.asyncio as aioredis

from ..core.logging import get_logger

logger = get_logger("rate_limiter")


class RateLimitExceeded(Exception):
    """Raised when a rate limit is exceeded."""
    def __init__(self, limit: str, retry_after: Optional[int] = None):
        self.limit = limit
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded: {limit}")


class RateLimiter:
    """Redis sliding-window rate limiter."""

    def __init__(self, redis: aioredis.Redis):
        self.redis = redis

    async def check(
        self,
        key: str,
        max_count: int,
        window_seconds: int,
        *,
        increment: bool = True,
    ) -> bool:
        """
        Check if key is within rate limit.
        Returns True if allowed, raises RateLimitExceeded if not.
        """
        now = time.time()
        window_start = now - window_seconds
        pipe_key = f"rl:{key}"

        pipe = self.redis.pipeline()
        # Remove old entries
        pipe.zremrangebyscore(pipe_key, 0, window_start)
        # Count current entries
        pipe.zcard(pipe_key)
        if increment:
            pipe.zadd(pipe_key, {f"{now}": now})
        pipe.expire(pipe_key, window_seconds + 1)
        results = await pipe.execute()

        current_count = results[1]
        if current_count >= max_count:
            retry_after = int(window_seconds - (now - window_start))
            raise RateLimitExceeded(
                limit=key.split(":")[0],
                retry_after=max(1, retry_after),
            )
        return True

    async def check_email_scan(self, email_hmac: str) -> bool:
        """3 scans per day per email-HMAC."""
        return await self.check(f"scan_email:{email_hmac}", 3, 86400)

    async def check_email_otp(self, email_hmac: str) -> bool:
        """1 OTP per 10 minutes per email-HMAC."""
        return await self.check(f"otp_email:{email_hmac}", 1, 600)

    async def check_ip_requests(self, ip_hash: str) -> bool:
        """10 requests per hour per IP."""
        return await self.check(f"ip_req:{ip_hash}", 10, 3600)

    async def check_ip_verify(self, ip_hash: str) -> bool:
        """30 verify attempts per hour per IP."""
        return await self.check(f"ip_verify:{ip_hash}", 30, 3600)

    async def check_disposable_scan(self, email_hmac: str) -> bool:
        """Stricter limit for disposable domains: 1 scan per day."""
        return await self.check(f"disp_scan:{email_hmac}", 1, 86400)
