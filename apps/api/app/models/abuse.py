"""Abuse-prevention models – sliding-window rate-limit counters."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AbuseCounter(Base):
    """Sliding-window counter keyed by an HMAC of the rate-limit subject."""

    __tablename__ = "abuse_counters"

    key_hmac: Mapped[str] = mapped_column(String(128), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
