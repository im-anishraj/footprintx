"""Audit-event model – immutable log of scan lifecycle events."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.scan import Scan


class AuditEvent(Base):
    """Append-only audit record attached to a scan. Never store PII in *meta*."""

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(
        pg.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        pg.UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    event: Mapped[str] = mapped_column(String(64), nullable=False)
    meta: Mapped[Optional[dict]] = mapped_column(
        pg.JSONB, nullable=True
    )  # NO PII in meta!
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scan: Mapped[Scan] = relationship(back_populates="audit_events")
