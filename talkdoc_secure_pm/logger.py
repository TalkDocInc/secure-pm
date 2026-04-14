"""Logging setup for talkdoc_secure_pm.

Imports loguru if available and falls back to stdlib logging.
Call configure_logging() once at program startup to apply formatting;
do *not* call it from library code so that importing the package does
not alter the host application's logging configuration.
"""

import sys
import logging

try:
    from loguru import logger  # type: ignore[assignment]
    HAS_LOGURU = True
except ImportError:
    logger = logging.getLogger("talkdoc_secure_pm")  # type: ignore[assignment]
    if not logger.handlers:
        _handler = logging.StreamHandler(sys.stderr)
        _handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(levelname)s | %(name)s:%(lineno)d | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(_handler)
    logger.setLevel(logging.INFO)
    HAS_LOGURU = False


def configure_logging(level: str = "INFO", diagnose: bool = False, colorize: bool = True) -> None:
    """Configure loguru for secure-pm when explicitly requested.

    This avoids changing global logging behaviour as a side-effect of
    importing the package.  Call this once from the CLI entry-point or
    main script, not from library code.
    """
    if HAS_LOGURU:
        logger.remove()
        logger.add(
            sys.stderr,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{line} | {message}",
            level=level,
            colorize=colorize,
            diagnose=diagnose,
        )
    else:
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))