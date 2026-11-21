"""Data models for scanner results."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class ScanFinding:
    """A single finding from a scanner module."""
    service_id: str
    service_name: str
    category: str
    sensitivity: str
    status: str  # indicator_found | likely | not_detected | unknown | rate_limited | unable_to_verify | skipped
    status_label: str
    confidence: str  # high | medium | low
    evidence_type: str
    engine: dict[str, Any] = field(default_factory=dict)
    checked_at: str = ""
    explanation: str = ""
    actions: list[dict[str, Any]] = field(default_factory=list)
    guide_id: Optional[str] = None
    guide_title: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BreachInfo:
    """Breach information from HIBP."""
    name: str
    date: str
    data_classes: list[str] = field(default_factory=list)
    description: str = ""
    actions: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResultPayload:
    """Complete scan result payload."""
    findings: list[ScanFinding] = field(default_factory=list)
    breaches: list[BreachInfo] = field(default_factory=list)
    modules_total: int = 0
    modules_done: int = 0
    modules_failed: int = 0
    coverage: dict[str, int] = field(default_factory=dict)
    actions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    masked_email: str = "***@***.***"
    hibp_available: bool = True
    empty_state_text: str = "No accounts detected by these checks. That isn't a guarantee."

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "breaches": [b.to_dict() for b in self.breaches],
            "modules_total": self.modules_total,
            "modules_done": self.modules_done,
            "modules_failed": self.modules_failed,
            "coverage": self.coverage,
            "actions": self.actions,
            "masked_email": self.masked_email,
            "hibp_available": self.hibp_available,
            "empty_state_text": self.empty_state_text,
        }
