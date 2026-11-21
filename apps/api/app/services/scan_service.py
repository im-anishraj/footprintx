"""Scan lifecycle and state machine service."""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.security import (
    decrypt_payload,
    encrypt_payload,
    hash_ip,
    hmac_sha256,
)
from ..core.logging import get_logger
from ..models.scan import (
    AbuseCounter,
    AuditEvent,
    Scan,
    ScanResult,
    ScanState,
    VerificationChallenge,
)

logger = get_logger("scan_service")

# Email validation
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
_MAX_EMAIL_LEN = 254

# Disposable domains list (lazy-loaded)
_disposable_domains: set[str] | None = None


def _load_disposable_domains() -> set[str]:
    global _disposable_domains
    if _disposable_domains is None:
        path = Path(__file__).parent.parent / "data" / "disposable_domains.txt"
        if path.exists():
            _disposable_domains = {
                line.strip().lower()
                for line in path.read_text().splitlines()
                if line.strip() and not line.startswith("#")
            }
        else:
            _disposable_domains = set()
    return _disposable_domains


def normalise_email(email: str) -> str:
    """Normalise an email: lowercase, strip, punycode domain."""
    email = email.strip().lower()
    if "@" in email:
        local, domain = email.rsplit("@", 1)
        try:
            domain = domain.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            pass
        email = f"{local}@{domain}"
    return email


def validate_email(email: str) -> tuple[bool, str]:
    """Validate email format. Returns (is_valid, error_message)."""
    if not email or len(email) > _MAX_EMAIL_LEN:
        return False, "Invalid email address"
    if not _EMAIL_RE.match(email):
        return False, "Invalid email address"
    return True, ""


def is_disposable_domain(email: str) -> bool:
    """Check if email uses a disposable domain."""
    domains = _load_disposable_domains()
    if "@" not in email:
        return False
    domain = email.rsplit("@", 1)[1].lower()
    return domain in domains


def email_hmac(email: str) -> str:
    """HMAC the normalised email with server pepper."""
    settings = get_settings()
    return hmac_sha256(normalise_email(email), settings.server_pepper)


async def create_scan(
    db: AsyncSession,
    email_hash: str,
    consent_version: str,
    client_ip: str,
) -> Scan:
    """Create a new scan in pending_verification state."""
    now = datetime.now(timezone.utc)
    scan = Scan(
        id=uuid.uuid4(),
        email_hmac=email_hash,
        state=ScanState.pending_verification,
        consent_version=consent_version,
        consented_at=now,
        ip_hash=hash_ip(client_ip),
        created_at=now,
    )
    db.add(scan)

    # Audit event
    audit = AuditEvent(
        scan_id=scan.id,
        event="scan_created",
        meta={"consent_version": consent_version},
    )
    db.add(audit)

    await db.flush()
    return scan


async def mark_verified(db: AsyncSession, scan: Scan) -> None:
    """Transition scan to queued state after verification."""
    now = datetime.now(timezone.utc)
    scan.state = ScanState.queued
    scan.verified_at = now
    scan.expires_at = now + timedelta(hours=24)

    audit = AuditEvent(
        scan_id=scan.id,
        event="scan_verified",
    )
    db.add(audit)
    await db.flush()


async def update_scan_progress(
    db: AsyncSession,
    scan_id: uuid.UUID,
    state: ScanState,
    modules_total: int,
    modules_done: int,
    modules_failed: int,
) -> None:
    """Update scan progress."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan:
        scan.state = state
        scan.modules_total = modules_total
        scan.modules_done = modules_done
        scan.modules_failed = modules_failed
        await db.flush()


async def store_results(
    db: AsyncSession,
    scan_id: uuid.UUID,
    results_data: dict[str, Any],
) -> None:
    """Encrypt and store scan results."""
    settings = get_settings()
    plaintext = json.dumps(results_data).encode("utf-8")
    encrypted, key_id = encrypt_payload(plaintext, settings.master_key)

    result = ScanResult(
        scan_id=scan_id,
        payload_enc=encrypted,
        key_id=key_id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db.add(result)

    audit = AuditEvent(
        scan_id=scan_id,
        event="results_stored",
        meta={"key_id": key_id},
    )
    db.add(audit)
    await db.flush()


async def get_results(
    db: AsyncSession, scan_id: uuid.UUID
) -> Optional[dict[str, Any]]:
    """Decrypt and return scan results."""
    settings = get_settings()
    result = await db.execute(
        select(ScanResult).where(ScanResult.scan_id == scan_id)
    )
    scan_result = result.scalar_one_or_none()
    if scan_result is None:
        return None

    try:
        plaintext = decrypt_payload(scan_result.payload_enc, settings.master_key)
        return json.loads(plaintext)
    except Exception:
        logger.exception("result_decryption_error", scan_id=str(scan_id))
        return None


async def get_scan(
    db: AsyncSession, scan_id: uuid.UUID
) -> Optional[Scan]:
    """Get a scan by ID."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    return result.scalar_one_or_none()


async def delete_scan(db: AsyncSession, scan_id: uuid.UUID) -> bool:
    """Hard-delete a scan and all related data."""
    scan = await get_scan(db, scan_id)
    if scan is None:
        return False

    # Delete results, challenges, audit events (cascade)
    await db.delete(scan)

    logger.info("scan_deleted", scan_id=str(scan_id))
    await db.flush()
    return True


async def purge_expired(db: AsyncSession) -> int:
    """Purge expired scans and results. Returns count of purged scans."""
    now = datetime.now(timezone.utc)
    count = 0

    # Find expired scans
    result = await db.execute(
        select(Scan)
        .where(Scan.expires_at.isnot(None))
        .where(Scan.expires_at < now)
        .where(Scan.state.notin_([ScanState.expired, ScanState.deleted]))
    )
    expired_scans = result.scalars().all()

    for scan in expired_scans:
        scan.state = ScanState.expired
        # Delete the encrypted results
        await db.execute(
            delete(ScanResult).where(ScanResult.scan_id == scan.id)
        )
        await db.execute(
            delete(VerificationChallenge).where(VerificationChallenge.scan_id == scan.id)
        )
        audit = AuditEvent(
            scan_id=scan.id,
            event="scan_expired",
        )
        db.add(audit)
        count += 1

    if count > 0:
        logger.info("purge_completed", count=count)
        await db.flush()

    return count


def get_service_catalog() -> list[dict[str, Any]]:
    """Load the service catalog from YAML."""
    import yaml
    path = get_settings().project_root / "content" / "services.yaml"
    if not path.exists():
        return []
    with open(path) as f:
        data = yaml.safe_load(f)
    return data.get("services", [])


def get_enabled_services() -> list[dict[str, Any]]:
    """Get only enabled services from the catalog."""
    return [s for s in get_service_catalog() if s.get("enabled", False)]


def get_guide(service_id: str) -> Optional[dict[str, Any]]:
    """Load a fix guide by service ID."""
    import yaml
    path = get_settings().project_root / "content" / "guides" / f"{service_id}.yaml"
    if not path.exists():
        return None
    with open(path) as f:
        return yaml.safe_load(f)


def get_all_guides() -> list[dict[str, Any]]:
    """Load all fix guides."""
    import yaml
    guides_dir = get_settings().project_root / "content" / "guides"
    guides = []
    if guides_dir.exists():
        for path in sorted(guides_dir.glob("*.yaml")):
            with open(path) as f:
                guide = yaml.safe_load(f)
                if guide:
                    guides.append(guide)
    return guides
