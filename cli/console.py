"""
Shared Rich console factory using the Opus 5.5 theme.

Honours ``NO_COLOR`` (via Rich) and the saved/ENV theme preference.
"""

from __future__ import annotations

import sys

from rich.console import Console

from cli.tui.theme import (
    preferred_theme_name,
    resolve_theme_name,
    set_active_palette,
    to_rich_theme,
)

_console: Console | None = None


def get_console() -> Console:
    """Process-wide console. Import-safe: no database access here."""
    global _console
    if _console is None:
        from config.settings import get_settings

        palette = set_active_palette(resolve_theme_name(get_settings().theme or None))
        _console = Console(theme=to_rich_theme(palette), highlight=False)
    return _console


_err_console: Console | None = None


def get_err_console() -> Console:
    """Console bound to stderr for warnings/progress (keeps stdout clean)."""
    global _err_console
    if _err_console is None:
        get_console()
        _err_console = Console(stderr=True, theme=to_rich_theme_active())
    return _err_console


def to_rich_theme_active():
    from cli.tui.theme import active_palette

    return to_rich_theme(active_palette())


def apply_cli_theme(name: str | None = None) -> str:
    """Apply the saved/explicit theme to the shared console at runtime."""
    chosen = resolve_theme_name(name) if name else preferred_theme_name()
    palette = set_active_palette(chosen)
    get_console().push_theme(to_rich_theme(palette))
    return chosen


def is_interactive() -> bool:
    """True when both stdin and stdout are terminals (TUI can run)."""
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False
