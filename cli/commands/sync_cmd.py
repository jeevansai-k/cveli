"""
CLI Sync Command.

Purpose: Synchronize vulnerability feeds into the local database.
"""

from __future__ import annotations

from typing import Annotated

import typer
from rich.markup import escape

from cli.console import get_console
from services.sync import ALL_SOURCES, SyncService

console = get_console()


def sync_command(
    sources: Annotated[
        list[str] | None,
        typer.Option(
            "--source",
            "-s",
            help=f"Sources to sync (repeatable): {', '.join(ALL_SOURCES)}, all",
        ),
    ] = None,
    query: str = typer.Option(
        "", "--query", "-q", help="Optional search query filter for feed fetch"
    ),
    limit: int = typer.Option(
        100, "--limit", "-l", min=1, max=20000, help="Maximum records per source"
    ),
    force: bool = typer.Option(
        False, "--force", help="Refresh cached catalogues (CISA KEV) even if fresh"
    ),
):
    """Synchronize CVE data from external feeds into the local database."""
    selected = sources or ["nvd", "cisa_kev"]
    unknown = sorted(set(selected) - {*ALL_SOURCES, "all", "kev", "cve.org"})
    if unknown:
        raise typer.BadParameter(
            f"Unknown source(s): {', '.join(unknown)}", param_hint="--source"
        )
    console.print(f"[title]Synchronizing:[/title] {', '.join(selected)}")
    with console.status("[info]Fetching external vulnerability feeds…[/info]"):
        res = SyncService().sync_sources(
            sources=selected, query=query, limit=limit, force=force
        )
    console.print(f"[success]✓ Stored {res['total_synced']} record(s)[/success]")
    for src, count in res.get("sources", {}).items():
        note = ""
        if src == "cisa_kev" and count == 0 and src not in res.get("errors", {}):
            note = " (catalogue still fresh — use --force to refresh)"
        console.print(f" • {src}: {count} fetched{note}")
    for src, error in res.get("errors", {}).items():
        console.print(f"[danger] ✗ {src} failed:[/danger] {escape(str(error))}")
    if res.get("errors") and not res["total_synced"]:
        raise typer.Exit(code=1)
