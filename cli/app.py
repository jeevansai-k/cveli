"""
CLI Application Entry Point.

Purpose: Typer application wiring every ``cveli`` sub-command; launches the
Textual shell when invoked without a sub-command on a terminal.
"""

from __future__ import annotations

import typer

from cli.branding import APP_HELP, EXPORT_HELP, SEARCH_HELP
from cli.commands.export_cmd import export_command
from cli.commands.search_cmd import search_command
from cli.commands.stats_cmd import stats_command
from cli.commands.sync_cmd import sync_command
from cli.commands.watchlist_cmd import watchlist_app
from cli.console import apply_cli_theme, get_console, is_interactive
from config.version import __version__

console = get_console()

app = typer.Typer(
    name="cveli",
    help=APP_HELP,
    add_completion=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)

app.command(
    "search",
    help=SEARCH_HELP,
    short_help="Search CVE vulnerabilities.",
)(search_command)
app.command("sync", short_help="Synchronize CVE feeds into the local database.")(
    sync_command
)
app.command(
    "export",
    help=EXPORT_HELP,
    short_help="Export stored CVE records to a file.",
)(export_command)
app.command("stats", short_help="Show database statistics.")(stats_command)
app.add_typer(watchlist_app, name="watchlist")


def _register_optional_commands() -> None:
    from cli.commands import register_extensions

    register_extensions(app)


_register_optional_commands()


def _launch_shell() -> None:
    from cli.tui.app import CveliApp

    CveliApp().run()


@app.command("tui")
def tui_command():
    """Launch the interactive Textual TUI dashboard."""
    _launch_shell()


@app.command("version")
def version_command():
    """Display application version."""
    console.print(
        f"[brand]cveli[/brand] v{__version__} - Search-First CVE CLI/TUI Tool"
    )


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version information"
    ),
    theme: str | None = typer.Option(
        None, "--theme", help="Theme for this run: dark, light or auto"
    ),
):
    """cveli - CVE Search & Vulnerability Management CLI/TUI Tool."""
    if version:
        version_command()
        raise typer.Exit()
    try:
        apply_cli_theme(theme)
    except Exception:  # theming must never block the CLI
        pass

    if ctx.invoked_subcommand is None:
        if not is_interactive():
            console.print(ctx.get_help())
            raise typer.Exit()
        _launch_shell()
