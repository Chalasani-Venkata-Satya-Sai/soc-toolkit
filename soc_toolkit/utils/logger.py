"""Shared logging setup using `rich` for readable, colorized SOC console output."""
from __future__ import annotations

import logging

from rich.logging import RichHandler


def get_logger(name: str = "soc_toolkit") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured

    handler = RichHandler(show_time=True, show_path=False, markup=True)
    handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))

    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger
