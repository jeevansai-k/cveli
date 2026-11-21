"""
CLI Application Entry Point.

Purpose: Provide the main command-line interface for cveli.
Inputs: Command-line arguments from typer.
Outputs: Terminal rendering (Textual TUI or rich console text).
Responsibilities: Command registration, parameter routing, entry-point handling.
Dependencies: typer, rich, cli.commands, cli.tui.main.
"""

import typer
from rich.console import Console

from cli.branding import APP_HELP, EXPORT_HELP, SEARCH_HELP
from cli.commands.export_cmd import export_command
from cli.commands.search_cmd import search_command
from cli.commands.stats_cmd import stats_command
from cli.commands.sync_cmd import sync_command
from cli.commands.watchlist_cmd import watchlist_app
from config.version import __version__

console = Console()

app = typer.Typer(
    name="cveli",
    help=APP_HELP,
    add_completion=False,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)

# Register subcommands
app.command(
    "search",
    help=SEARCH_HELP,
    short_help="Search CVE vulnerabilities.",
)(search_command)
app.command("sync")(sync_command)
app.command(
    "export",
    help=EXPORT_HELP,
    short_help="Export stored CVE records to a file.",
)(export_command)
app.command("stats")(stats_command)
app.add_typer(watchlist_app, name="watchlist")


@app.command("tui")
def tui_command():
    """Launch the interactive Textual TUI dashboard."""
    from cli.tui.main import MainApp

    tui_app = MainApp()
    tui_app.run()


@app.command("version")
def version_command():
    """Display application version."""
    console.print(f"[bold]cveli[/bold] v{__version__} - Search-First CVE CLI/TUI Tool")


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-v", help="Show version information"
    ),
):
    """cveli - CVE Search & Vulnerability Management CLI/TUI Tool."""
    if version:
        version_command()
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        # Launch TUI by default when no subcommand is provided
        from cli.tui.main import MainApp

        tui_app = MainApp()
        tui_app.run()
