"""``cveli settings`` — theme, motion and effective configuration."""

from __future__ import annotations

import typer
from rich.table import Table
from rich.text import Text

from cli.commands.common import console, emit_json
from cli.tui.theme import THEME_CHOICES, theme_label
from config.settings import get_settings
from storage.system_repositories import SettingsRepository

settings_app = typer.Typer(
    help="View and change CVELI preferences.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)


@settings_app.command("theme")
def theme_command(
    choice: str = typer.Argument(None, help="dark, light or auto (omit to show)"),
):
    """Show or persist the theme preference (dark, light or auto)."""
    repo = SettingsRepository()
    if choice is None:
        saved = repo.get("theme", "auto")
        console.print(f"Theme preference: {saved} (active: {theme_label(saved)})")
        return
    choice = choice.lower().strip()
    if choice not in THEME_CHOICES:
        raise typer.BadParameter(f"Use one of: {', '.join(THEME_CHOICES)}")
    repo.set("theme", choice)
    console.print(f"[success]✓ Theme set to {choice}[/success]")


@settings_app.command("motion")
def motion_command(
    reduce: bool = typer.Option(..., "--reduce/--full", help="Reduce or allow motion"),
):
    """Persist the reduced-motion preference for the TUI."""
    SettingsRepository().set("reduce_motion", reduce)
    console.print(f"[success]✓ Reduced motion {'on' if reduce else 'off'}[/success]")


@settings_app.command("show")
def show_command(
    as_json: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Show effective configuration (secrets masked) and saved preferences."""
    data = {**get_settings().redacted(), "saved": SettingsRepository().all()}
    if as_json:
        emit_json(data)
        return
    table = Table(title="Effective settings", expand=True)
    table.add_column("Key", style="title")
    table.add_column("Value")
    for key, value in data.items():
        table.add_row(key, Text(str(value)))
    console.print(table)
