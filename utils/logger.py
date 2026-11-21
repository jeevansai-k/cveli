"""
Logger Configuration and Utilities.

Purpose: Centralized loguru configuration with privacy redaction.
Responsibilities:
    - Write rotating debug logs to the CVELI log directory (never the terminal UI).
    - Redact secrets (API keys) and user-entered research inputs (usernames,
      target domains, generated dorks) before anything reaches disk.

Example:
    from utils.logger import get_logger, sensitive

    log = get_logger(__name__)
    with sensitive("alice", "example.com"):
        log.info("building dork for alice")  # -> "building dork for [REDACTED]"
"""

from __future__ import annotations

import logging
import re
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from loguru import logger

_CONFIGURED = False
_SENSITIVE: dict[str, int] = {}
_SENSITIVE_LOCK = threading.Lock()
REDACTED = "[REDACTED]"
_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|apikey|token|secret|password)(\s*[=:]\s*)\S+"),
]


def register_sensitive(*values: str) -> None:
    with _SENSITIVE_LOCK:
        for value in values:
            if value and len(value.strip()) >= 2:
                key = value.strip()
                _SENSITIVE[key] = _SENSITIVE.get(key, 0) + 1


def unregister_sensitive(*values: str) -> None:
    with _SENSITIVE_LOCK:
        for value in values:
            key = (value or "").strip()
            if key in _SENSITIVE:
                _SENSITIVE[key] -= 1
                if _SENSITIVE[key] <= 0:
                    del _SENSITIVE[key]


@contextmanager
def sensitive(*values: str) -> Iterator[None]:
    """Redact ``values`` from every log line emitted inside the block."""
    register_sensitive(*values)
    try:
        yield
    finally:
        unregister_sensitive(*values)


def redact(message: str) -> str:
    for pattern in _SECRET_PATTERNS:
        message = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", message)
    with _SENSITIVE_LOCK:
        values = sorted(_SENSITIVE, key=len, reverse=True)
    for value in values:
        message = re.sub(re.escape(value), REDACTED, message, flags=re.IGNORECASE)
    return message


def _patch(record) -> None:
    record["message"] = redact(str(record["message"]))


def _log_dir() -> Path:
    try:
        from config.settings import get_settings

        return get_settings().log_dir
    except Exception:  # pragma: no cover - defensive during early import
        return Path.home() / ".cache" / "cveli" / "logs"


def setup_root_logger(force: bool = False) -> None:
    """Configure std logging + loguru once (idempotent)."""
    global _CONFIGURED
    if _CONFIGURED and not force:
        return
    root = logging.getLogger()
    root.setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    logger.remove()
    logger.configure(patcher=_patch)
    for candidate in (_log_dir(), Path(tempfile.gettempdir()) / "cveli"):
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            logger.add(
                candidate / "cveli.log", level="DEBUG", rotation="1 MB", retention=3
            )
            break
        except OSError:
            continue
    _CONFIGURED = True


def get_logger(module_name: str, level: int = logging.INFO):
    """Factory function to create a named logger."""
    return logger.bind(name=module_name)


setup_root_logger()
