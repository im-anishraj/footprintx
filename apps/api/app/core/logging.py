"""Structured JSON logging with PII redaction processor."""
from __future__ import annotations

import logging
import re
import sys
from typing import Any

import structlog


# Patterns that must NEVER appear in logs
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_OTP_CONTEXT_RE = re.compile(r"\b(otp|code|verification)[\"']?\s*[:=]\s*[\"']?\d{4,8}[\"']?", re.IGNORECASE)
_TOKEN_RE = re.compile(r"(token|magic|session)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_-]{16,}[\"']?", re.IGNORECASE)
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9_-]{16,}", re.IGNORECASE)

_REDACTED = "[REDACTED]"


def _redact_value(value: Any) -> Any:
    """Redact sensitive patterns from a single value."""
    if not isinstance(value, str):
        return value
    result = value
    result = _EMAIL_RE.sub(_REDACTED, result)
    result = _OTP_CONTEXT_RE.sub(_REDACTED, result)
    result = _TOKEN_RE.sub(_REDACTED, result)
    result = _IP_RE.sub(_REDACTED, result)
    result = _BEARER_RE.sub(_REDACTED, result)
    return result


def redact_processor(
    logger: Any, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Structlog processor that redacts PII from all log fields."""
    for key, value in list(event_dict.items()):
        if isinstance(value, str):
            event_dict[key] = _redact_value(value)
        elif isinstance(value, dict):
            event_dict[key] = {
                k: _redact_value(v) for k, v in value.items()
            }
        elif isinstance(value, (list, tuple)):
            event_dict[key] = type(value)(_redact_value(v) for v in value)
    return event_dict


def setup_logging(json_output: bool = True) -> None:
    """Configure structlog with redaction processor."""
    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        redact_processor,
    ]

    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=logging.INFO,
    )


def get_logger(name: str = "footprintx") -> structlog.stdlib.BoundLogger:
    """Get a bound logger instance."""
    return structlog.get_logger(name)
