"""Structured logging for RevoSec."""

import logging
import sys
from pathlib import Path
from rich.logging import RichHandler
from rich.console import Console

console = Console()

LOG_DIR = Path.home() / ".revosec" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


def setup_logger(name: str = "revosec", level: int = logging.INFO) -> logging.Logger:
    """Configure and return a logger with Rich console + file handlers."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers
    if logger.handlers:
        return logger

    # Console handler with Rich
    console_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        markup=True,
    )
    console_handler.setLevel(level)
    console_handler.setFormatter(logging.Formatter("%(message)s"))

    # File handler
    file_handler = logging.FileHandler(LOG_DIR / "revosec.log", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


logger = setup_logger()
