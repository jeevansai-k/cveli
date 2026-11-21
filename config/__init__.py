"""
Configuration Module.

Purpose: Centralized, typed access to application settings.

Example:
    from config.settings import get_settings

    settings = get_settings()
    settings.db_path, settings.nvd_api_key
"""

from .settings import Settings, get_setting, get_settings, reset_settings
from .version import __version__

__all__ = ["Settings", "get_setting", "get_settings", "reset_settings", "__version__"]
