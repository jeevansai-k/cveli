"""
CLI Sync Command.

Purpose: Synchronize vulnerability feeds into local SQLite.
Inputs: Source flags, query keyword, item limit.
Outputs: Progress log and summary metrics.
Responsibilities: Execute SyncService and report progress.
Dependencies: typer, rich, services.sync.
"""

from typing import Annotated

import typer
from rich.console import Console
from rich.status import Status

from services.sync import SyncService

console = Console()


def sync_command(
    sources: Annotated[
        list[str] | None,
        typer.Option("--source", "-s", help="Sources to sync"),
    ] = None,
    query: str = typer.Option(
        "", "--query", "-q", help="Optional search query filter for feed fetch"
    ),
    limit: int = typer.Option(100, "--limit", "-l", help="Maximum records per source"),
):
    """Synchronize CVE data from external feeds into local database."""
    selected_sources = sources or ["nvd", "cisa_kev"]
    source_text = ", ".join(selected_sources)
    console.print(
        "[bold cyan]Starting CVE synchronization for sources:[/bold cyan] "
        f"{source_text}"
    )

    sync_service = SyncService()

    with Status(
        "[bold green]Fetching external vulnerability feeds...", console=console
    ):
        res = sync_service.sync_sources(
            sources=selected_sources, query=query, limit=limit
        )

    console.print("[bold green]✓ Synchronization complete![/bold green]")
    console.print(
        "Total synchronized records stored: "
        f"[bold cyan]{res['total_synced']}[/bold cyan]"
    )
    for src, count in res.get("sources", {}).items():
        console.print(f" • {src}: {count} fetched")
