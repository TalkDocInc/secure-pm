"""Central logging helpers for the talkdoc_secure_pm package."""

from __future__ import annotations

import logging
import sys

__all__ = ["logger", "configure_logging", "HAS_LOGURU"]

try:
    from loguru import logger as _loguru_logger
except ImportError:
    _loguru_logger = None
    HAS_LOGURU = False
else:
    HAS_LOGURU = True


def _build_stdlib_logger() -> logging.Logger:
    logger = logging.getLogger("talkdoc_secure_pm")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(levelname)s | %(name)s:%(lineno)d | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


logger = _loguru_logger if HAS_LOGURU else _build_stdlib_logger()


def configure_logging(level: str = "INFO", diagnose: bool = False, colorize: bool = True) -> None:
    """Configure package logging when explicitly requested by the CLI."""
    if HAS_LOGURU:
        _loguru_logger.remove()
        _loguru_logger.add(
            sys.stderr,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{line} | {message}",
            level=level,
            colorize=colorize,
            diagnose=diagnose,
        )
    else:
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))

