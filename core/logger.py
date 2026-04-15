"""
core/logger.py — Structured logger for the AI API Testing Framework
"""
import logging
import sys
from datetime import datetime
from pathlib import Path
from rich.logging import RichHandler
from rich.console import Console

console = Console()

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # Rich console handler
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
    )
    rich_handler.setLevel(logging.DEBUG)

    # File handler
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    file_handler = logging.FileHandler(log_dir / f"aitesting_{date_str}.log")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(name)s | %(levelname)s | %(message)s")
    )

    logger.addHandler(rich_handler)
    logger.addHandler(file_handler)
    return logger
