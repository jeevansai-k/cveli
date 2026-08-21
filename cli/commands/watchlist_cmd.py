"""
CLI Watchlist Commands.

Purpose: Manage monitored vendors/products/CWE targets.
Inputs: Target type, target value, notes, action (add, list, remove, check).
Outputs: Rich tables of watchlist items and active alerts.
Responsibilities: Delegate to WatchlistService and display results.
Dependencies: typer, rich, services.watchlist.
"""

import typer
from rich.console import Console
from rich.table import Table

from services.watchlist import WatchlistService

console = Console()
watchlist_app = typer.Typer(
    name="watchlist", help="Manage monitored vendors, products, and CWE targets"
)


@watchlist_app.command("add")
def watchlist_add(
    target_type: str = typer.Option(
        ..., "--type", "-t", help="Target type (vendor, product, cwe)"
    ),
    value: str = typer.Option(
        ..., "--value", "-v", help="Target value (e.g. 'OpenSSL', 'Apache', 'CWE-79')"
    ),
    notes: str = typer.Option("", "--notes", "-n", help="Optional notes/description"),
):
    """Add a vendor, product, or CWE to monitored watchlist."""
    service = WatchlistService()
    res = service.add_target(target_type=target_type, target_value=value, notes=notes)
    console.print(
        "[bold green]✓ Added to watchlist:[/bold green] "
        f"{res['target_type'].upper()} -> [cyan]{res['target_value']}[/cyan]"
    )


@watchlist_app.command("list")
def watchlist_list():
    """List all monitored targets in the watchlist."""
    service = WatchlistService()
    items = service.list_targets()

    if not items:
        console.print(
            "[yellow]Watchlist is currently empty. "
            "Add targets using 'cveli watchlist add'.[/yellow]"
        )
        return

    table = Table(
        title=f"Monitored Watchlist Targets ({len(items)} items)", expand=True
    )
    table.add_column("ID", style="dim", width=12)
    table.add_column("Target Type", style="bold cyan", width=12)
    table.add_column("Value / Name", style="bold yellow", width=25)
    table.add_column("Added At", style="dim", width=19)
    table.add_column("Notes", style="white")

    for item in items:
        table.add_row(
            item["id"][:8],
            item["target_type"].upper(),
            item["target_value"],
            item["created_at"][:19],
            item.get("notes", ""),
        )

    console.print(table)


@watchlist_app.command("remove")
def watchlist_remove(
    target_id: str = typer.Argument(
        ..., help="ID or value of watchlist item to remove"
    ),
):
    """Remove an item from the watchlist by ID or target value."""
    service = WatchlistService()
    success = service.remove_target(target_id)
    if success:
        console.print(
            "[bold green]✓ Successfully removed watchlist target:[/bold green] "
            f"[cyan]{target_id}[/cyan]"
        )
    else:
        console.print(f"[bold red]Watchlist target '{target_id}' not found.[/bold red]")


@watchlist_app.command("check")
def watchlist_check():
    """Evaluate database for vulnerability alerts matching watchlist items."""
    service = WatchlistService()
    res = service.check_alerts()

    watched = res["watchlist_count"]
    alerts = res["alert_count"]
    console.print(
        f"[bold cyan]Watchlist Alert Check:[/bold cyan] {watched} targets "
        f"monitored, [bold yellow]{alerts} alert matches found.[/bold yellow]\n"
    )

    for alert in res.get("alerts", []):
        item = alert["watchlist_item"]
        cves = alert["cves"]
        target = item["target_value"]
        target_type = item["target_type"].upper()
        match_count = alert["match_count"]
        console.print(
            f"[bold red]⚡ ALERT MATCH:[/bold red] {target_type} "
            f"[bold cyan]{target}[/bold cyan] ({match_count} CVEs matched)"
        )
        for cve in cves[:3]:
            summary = cve["summary"][:75]
            console.print(
                f"   • [cyan]{cve['id']}[/cyan] "
                f"({cve['severity']}) - {summary}..."
            )
        console.print("")
