"""
Logger Configuration and Utilities.

Purpose: Provide centralized logging configuration for the application.
Inputs: Log level, module name.
Outputs: Logger instances.
Responsibilities: Configure loguru, provide logger access pattern.
Dependencies: loguru (from requirements)

Functions/Classes:
    - get_logger(module_name): Factory function to create named loggers
    - configure(): Configuration entry point
    - setup_root_logger(): Setup the root logger instance

Example:
    from utils.logger import get_logger

    # Create a logger for this module
    log = get_logger(__name__)

    # Log messages at various levels
    log.info("Application started")
    log.warning("Cache miss detected")
    log.error("Failed to sync with NVD API")

"""

import logging
import tempfile
from pathlib import Path

from loguru import logger

_CONFIGURED = False


def setup_root_logger() -> None:
    """Setup the root logger instance."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    root = logging.getLogger()
    root.setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(console_formatter)

    if not root.handlers:
        root.addHandler(console_handler)
    logger.remove()
    log_dir = Path.home() / ".cache" / "cveli"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        log_dir = Path(tempfile.gettempdir()) / "cveli"
        log_dir.mkdir(parents=True, exist_ok=True)
    try:
        logger.add(log_dir / "cveli.log", level="DEBUG", rotation="1 MB", retention=3)
    except OSError:
        log_dir = Path(tempfile.gettempdir()) / "cveli"
        log_dir.mkdir(parents=True, exist_ok=True)
        logger.add(log_dir / "cveli.log", level="DEBUG", rotation="1 MB", retention=3)
    _CONFIGURED = True


def get_logger(module_name: str, level: int = logging.INFO):
    """Factory function to create a named logger."""
    return logger.bind(name=module_name)


# Initialize root logger once at module load time
setup_root_logger()
