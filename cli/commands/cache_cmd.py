"""``cveli cache`` — inspect and clean the local cache."""

from __future__ import annotations

import typer

from cli.commands.common import console, emit_json
from storage.cache import cache_cleanup, cache_clear, cache_stats

cache_app = typer.Typer(
    help="Inspect or clear the local query cache.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)


@cache_app.command("status")
def status(as_json: bool = typer.Option(False, "--json")):
    """Show cache size and location."""
    stats = cache_stats()
    if as_json:
        emit_json(stats)
    else:
        console.print(stats, markup=False)


@cache_app.command("clear")
def clear():
    """Delete all cached query results (stored CVEs are kept)."""
    cache_clear()
    console.print("[success]✓ Cache cleared[/success]")


@cache_app.command("cleanup")
def cleanup():
    """Expire stale entries and enforce the size limit."""
    console.print(cache_cleanup(), markup=False)
