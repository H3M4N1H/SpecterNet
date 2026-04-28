"""Lightweight logging helper for future reuse."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def get_logger(name: str = "SpecterNet", log_file: str | None = None) -> logging.Logger:
    """Return a configured logger with a console handler and optional file output."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=3)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger

