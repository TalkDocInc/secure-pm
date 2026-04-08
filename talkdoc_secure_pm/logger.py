import logging

try:
    from loguru import logger
except ImportError:
    logger = logging.getLogger(__name__)