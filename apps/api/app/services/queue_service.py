"""Queue service for scanner job dispatch and result retrieval."""
from __future__ import annotations

import json
from typing import Any, Optional

import redis.asyncio as aioredis

from ..core.config import get_settings
from ..core.logging import get_logger
from ..core.security import encrypt_queue_payload, decrypt_queue_payload

logger = get_logger("queue")

SCAN_QUEUE = "fpx:scan_jobs"
RESULT_PREFIX = "fpx:scan_result:"


async def enqueue_scan_job(
    redis: aioredis.Redis,
    scan_id: str,
    email: str,
) -> None:
    """Enqueue a scan job. Email is encrypted in transit."""
    settings = get_settings()
    payload = json.dumps({"scan_id": scan_id, "email": email}).encode()
    encrypted = encrypt_queue_payload(payload, settings.scanner_queue_key)

    await redis.lpush(SCAN_QUEUE, encrypted)
    logger.info("scan_job_enqueued", scan_id=scan_id)


async def get_scan_result(
    redis: aioredis.Redis,
    scan_id: str,
) -> Optional[dict[str, Any]]:
    """Check for scan results. Returns None if not ready."""
    result_key = f"{RESULT_PREFIX}{scan_id}"
    data = await redis.get(result_key)
    if data is None:
        return None

    settings = get_settings()
    try:
        decrypted = decrypt_queue_payload(data, settings.scanner_queue_key)
        return json.loads(decrypted)
    except Exception:
        logger.exception("result_decryption_error", scan_id=scan_id)
        return None


async def publish_scan_result(
    redis: aioredis.Redis,
    scan_id: str,
    result: dict[str, Any],
) -> None:
    """Publish scan results (called by worker)."""
    settings = get_settings()
    payload = json.dumps(result).encode()
    encrypted = encrypt_queue_payload(payload, settings.scanner_queue_key)

    result_key = f"{RESULT_PREFIX}{scan_id}"
    # Store with 1-hour TTL (results are also stored encrypted in DB)
    await redis.set(result_key, encrypted, ex=3600)

    # Publish notification
    await redis.publish(f"fpx:scan_done:{scan_id}", "done")
    logger.info("scan_result_published", scan_id=scan_id)
