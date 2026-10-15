"""Logging setup.

A single redaction filter guards every handler: API keys, bearer tokens, and
password-like values are masked before a record reaches any output stream. This
keeps credentials out of logs even if a caller logs a config object by mistake.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from typing import Any

REDACTION_PATTERNS = [
    # Authorization headers and bearer tokens.
    (re.compile(r"(?i)(authorization\s*[:=]\s*)(\S+)"), r"\1<redacted>"),
    (re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._\-]{8,})"), r"\1<redacted>"),
    # Common API key shapes (OpenAI-style, generic long hex/base64 secrets).
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}\b"), "<redacted-api-key>"),
    # Explicit key=value pairs.
    (
        re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd)\b(\s*[:=]\s*)(\S+)"),
        r"\1\2<redacted>",
    ),
]


class RedactionFilter(logging.Filter):
    """Mask credential-shaped substrings in log messages and arguments."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)
        if record.args:
            record.args = tuple(
                redact_text(arg) if isinstance(arg, str) else arg for arg in record.args
            )
        return True


def redact_text(text: str) -> str:
    result = text
    for pattern, replacement in REDACTION_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log record for machine-readable logs."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str = "INFO", fmt: str = "text") -> logging.Logger:
    """Configure the root logger once and return the project logger."""
    logger = logging.getLogger("scapy_ai_analyzer")
    logger.handlers.clear()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    handler = logging.StreamHandler(sys.stderr)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    handler.addFilter(RedactionFilter())
    logger.addHandler(handler)
    return logger
