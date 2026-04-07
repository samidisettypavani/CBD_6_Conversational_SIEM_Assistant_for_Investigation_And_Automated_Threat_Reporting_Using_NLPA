from __future__ import annotations

import logging

from .config import settings


LOG_FORMAT = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"


def configure_logging() -> None:
    level_name = settings.log_level.upper()
    level = getattr(logging, level_name, logging.INFO)

    logging.basicConfig(level=level, format=LOG_FORMAT, force=True)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
