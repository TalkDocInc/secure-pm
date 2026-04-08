# talkdoc_secure_pm package

import sys
import logging

try:
    from loguru import logger
    HAS_LOGURU = True
except ImportError:
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
    HAS_LOGURU = False

def configure_logging(level="INFO", diagnose=False, colorize=True):
    """Configure Loguru for secure-pm when explicitly requested.
    This avoids changing global logging behavior as a side effect of
    importing the package.
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
        # For standard logging, level can be set, but colorize/diagnose not supported
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))
