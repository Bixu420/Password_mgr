import logging
from logging.handlers import RotatingFileHandler

from .config import LOG_PATH


def setup_logger():
    logger = logging.getLogger("passmgr")
    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers if FastAPI reloads code
    if logger.handlers:
        return logger

    # Rotating file log: ~2MB per file, keep 5 backups
    handler = RotatingFileHandler(
        LOG_PATH,
        maxBytes=2_000_000,
        backupCount=5,
        encoding="utf-8"
    )

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s"
    )
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    logger.propagate = False

    logger.info("Logger initialized")

    return logger


logger = setup_logger()
