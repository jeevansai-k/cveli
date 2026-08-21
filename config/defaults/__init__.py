"""
Default Configuration Module.

Purpose: Provide sensible defaults for all configuration options.
Inputs: None (static values)
Outputs: Pre-configured dictionaries and settings objects.
Responsibilities: Define fallback behavior when user doesn't configure options.
Dependencies: None

Functions/Classes:
    - __init__.py: Re-export all default setting constants

Example:
    From cli/app.py:
        from config.defaults import DEFAULT_APP_SETTINGS, DEFAULT_SYNC_SETTINGS

        # Use defaults when user hasn't configured options
        rate_limit = get_setting("RATE_LIMIT_NVD", DEFAULT_SYNC_SETTINGS.rate_limit)
"""

# Re-export all defaults for convenient imports
from .defaults import *  # noqa
