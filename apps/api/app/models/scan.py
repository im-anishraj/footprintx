"""Scan domain models – core tables for the FootprintX scan lifecycle."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, LargeBinary, String
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


class ScanState(str, enum.Enum):
    """Finite-state values a Scan may occupy."""
    pending_verification = "pending_verification"
    queued = "queued"
    running = "running"
    completed = "completed"
    partial = "partial"
    failed = "failed"
    expired = "expired"
    deleted = "deleted"


class ResultStatus(str, enum.Enum):
    """Outcome classification for an individual scan result."""
    indicator_found = "indicator_found"
    likely = "likely"
    not_detected = "not_detected"
    unknown = "unknown"
    rate_limited = "rate_limited"
    unable_to_verify = "unable_to_verify"
    skipped = "skipped"


class ConfidenceLevel(str, enum.Enum):
    """How confident the system is in a given result."""
    high = "high"
    medium = "medium"
    low = "low"


class Scan(Base):
    """Primary scan record – one row per user-initiated scan request."""
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        pg.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email_hmac: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    state: Mapped[str] = mapped_column(
        String(32), default=ScanState.pending_verification.value, nullable=False
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
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    modules_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    modules_done: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    modules_failed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    challenges: Mapped[list["VerificationChallenge"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    results: Mapped[list["ScanResult"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    audit_events: Mapped[list["AuditEvent"]] = relationship(
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
        index=True,
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

    scan: Mapped["Scan"] = relationship(back_populates="challenges")


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
        unique=True,
        index=True,
    )
    payload_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False, default="v1")
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    scan: Mapped["Scan"] = relationship(back_populates="results")


class AbuseCounter(Base):
    """Rate-limit abuse counter using HMAC keys, 30-day retention."""
    __tablename__ = "abuse_counters"

    key_hmac: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    __table_args__ = (
        Index("ix_abuse_window", "key_hmac", "window_start"),
    )


class AuditEvent(Base):
    """Audit log — no PII in meta JSONB."""
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(
        pg.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        pg.UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event: Mapped[str] = mapped_column(String(50), nullable=False)
    meta: Mapped[Optional[dict]] = mapped_column(pg.JSONB, nullable=True, default=dict)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scan: Mapped["Scan"] = relationship(back_populates="audit_events")
