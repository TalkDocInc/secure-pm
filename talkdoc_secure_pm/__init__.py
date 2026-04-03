from loguru import logger
import sys

# Global logger for secure-pm
logger.remove()
logger.add(sys.stderr, format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{line} | {message}", level="INFO", colorize=True, diagnose=True)

__version__ = "0.3.0"

