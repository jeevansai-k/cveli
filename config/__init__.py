"""
Configuration Module.

Purpose: Provide centralized access to application settings and configuration.
Inputs: Environment variables, runtime requests for setting values.
Outputs: Configuration dictionaries and setting values.
Responsibilities: Manage all configuration-related operations.
Dependencies: python-dotenv for environment loading.

Functions/Classes:
    - settings.py: Default settings and environment variable handling

Example:
    From cli/app.py:
        from config.settings import get_setting, DEFAULT_SETTINGS

        # Get configured value with fallback to default
        rate_limit = get_setting("RATE_LIMIT_NVD", 30)

"""

# Re-export for convenient imports
from .settings import *  # noqa
