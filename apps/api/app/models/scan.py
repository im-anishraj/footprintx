"""Scan domain models – core tables for the FootprintX scan lifecycle."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, LargeBinary, String
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.audit import AuditEvent


class ScanState(str, enum.Enum):
    """Finite-state values a Scan may occupy."""

    PENDING_VERIFICATION = "pending_verification"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    EXPIRED = "expired"
    DELETED = "deleted"


class ResultStatus(str, enum.Enum):
    """Outcome classification for an individual scan result."""

    INDICATOR_FOUND = "indicator_found"
    LIKELY = "likely"
    NOT_DETECTED = "not_detected"
    UNKNOWN = "unknown"
    RATE_LIMITED = "rate_limited"
    UNABLE_TO_VERIFY = "unable_to_verify"
    SKIPPED = "skipped"


class ConfidenceLevel(str, enum.Enum):
    """How confident the system is in a given result."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Scan(Base):
    """Primary scan record – one row per user-initiated scan request."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        pg.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email_hmac: Mapped[str] = mapped_column(
        String(64), index=True, nullable=False
    )
    state: Mapped[str] = mapped_column(
        String(32), default=ScanState.PENDING_VERIFICATION.value, nullable=False
    )
    consent_version: Mapped[str] = mapped_column(String(16), nullable=False)
    consented_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    ip_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # Relationships
    challenges: Mapped[list[VerificationChallenge]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    results: Mapped[list[ScanResult]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    audit_events: Mapped[list[AuditEvent]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_scans_email_hmac_created", "email_hmac", "created_at"),
        Index("ix_scans_expires_at", "expires_at"),
    )


class VerificationChallenge(Base):
    """Email-verification challenge linked to a scan."""

    __tablename__ = "verification_challenges"

    id: Mapped[uuid.UUID] = mapped_column(
        pg.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        pg.UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    magic_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    consumed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    scan: Mapped[Scan] = relationship(back_populates="challenges")


class ScanResult(Base):
    """Encrypted scan-result payload stored per scan."""

    __tablename__ = "scan_results"

    id: Mapped[uuid.UUID] = mapped_column(
        pg.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        pg.UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    payload_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    scan: Mapped[Scan] = relationship(back_populates="results")
