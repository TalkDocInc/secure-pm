# talkdoc_secure_pm package
__all__ = ['logger']
try:
    from loguru import logger
    HAS_LOGURU = True
except ImportError:
    import logging
    import sys
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
    """Configure Loguru for secure-pm when explicitly requested."""
    if HAS_LOGURU:
        from loguru import logger
        logger.remove()
        logger.add(
            sys.stderr,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{line} | {message}",
            level=level,
            colorize=colorize,
            diagnose=diagnose,
        )
    else:
        import logging
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))

