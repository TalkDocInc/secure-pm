from loguru import logger
import sys

# Global logger for secure-pm
logger.remove()
logger.add(
    sys.stderr,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{line} | {message}",
    level="INFO",
    colorize=True,
    diagnose=True,
)

def configure_logging(level="INFO", diagnose=False, colorize=True):
    """Configure Loguru for secure-pm when explicitly requested.

    This avoids changing global logging behavior as a side effect of
    importing the package.
    """
    logger.remove()
    logger.add(
        sys.stderr,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{line} | {message}",
        level=level,
        colorize=colorize,
        diagnose=diagnose,
    )

__version__ = "0.3.0"

