"""
CLI Subcommands.

Core commands are imported directly by ``cli.app``; 2.0 feature commands are
registered through ``register_extensions`` so they honour feature flags.
"""

from __future__ import annotations

import typer

from .export_cmd import export_command
from .search_cmd import search_command
from .stats_cmd import stats_command
from .sync_cmd import sync_command
from .watchlist_cmd import watchlist_app

__all__ = [
    "search_command",
    "sync_command",
    "export_command",
    "watchlist_app",
    "stats_command",
    "register_extensions",
]


def register_extensions(app: typer.Typer) -> None:
    """Attach 2.0 command groups that exist in this build."""
    import importlib

    groups = [
        ("cli.commands.exploits_cmd", "exploits_app", "exploits"),
        ("cli.commands.dork_cmd", "dork_app", "dork"),
        ("cli.commands.msf_cmd", "msf_app", "msf"),
        ("cli.commands.project_cmd", "project_app", "project"),
        ("cli.commands.settings_cmd", "settings_app", "settings"),
        ("cli.commands.jobs_cmd", "jobs_app", "jobs"),
        ("cli.commands.privacy_cmd", "privacy_app", "privacy"),
        ("cli.commands.cache_cmd", "cache_app", "cache"),
    ]
    for module_name, attr, name in groups:
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError as error:
            if error.name == module_name:
                continue
            raise
        app.add_typer(getattr(module, attr), name=name)
    try:
        from .doctor_cmd import doctor_command
    except ModuleNotFoundError:
        return
    app.command("doctor", short_help="Diagnose settings, paths and data sources.")(
        doctor_command
    )
