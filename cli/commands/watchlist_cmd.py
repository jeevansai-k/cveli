"""
CLI Watchlist Commands.

Manage monitored vendors/products/CWEs and check for (new) matching CVEs.
Security (B8): every stored/feed value is escaped before Rich renders it.
"""

from __future__ import annotations

import typer
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from cli.console import get_console
from core.formatter import severity_label
from core.text import one_line
from services.watchlist import WatchlistService
from utils.errors import ValidationError

console = get_console()
watchlist_app = typer.Typer(
    name="watchlist",
    help="Manage monitored vendors, products, and CWE targets",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
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
    """Add a vendor, product, or CWE to the watchlist."""
    try:
        res = WatchlistService().add_target(
            target_type=target_type, target_value=value, notes=notes
        )
    except ValidationError as error:
        console.print(f"[danger]{escape(str(error))}[/danger]")
        raise typer.Exit(code=2) from error
    console.print(
        "[success]✓ Added to watchlist:[/success] "
        f"{res['target_type'].upper()} → [info]{escape(res['target_value'])}[/info]"
    )


@watchlist_app.command("list")
def watchlist_list():
    """List all monitored targets in the watchlist."""
    items = WatchlistService().list_targets()
    if not items:
        console.print(
            "[warning]Watchlist is empty. "
            "Add targets using 'cveli watchlist add'.[/warning]"
        )
        return

    table = Table(title=f"Watchlist ({len(items)} items)", expand=True)
    table.add_column("ID", style="muted", width=10)
    table.add_column("Type", style="title", width=9)
    table.add_column("Value", style="accent", width=25)
    table.add_column("Added", style="muted", width=19)
    table.add_column("Last check", style="muted", width=19)
    table.add_column("Notes")
    for item in items:
        table.add_row(
            item["id"][:8],
            item["target_type"].upper(),
            Text(item["target_value"]),
            item["created_at"][:19],
            item.get("last_checked_at", "")[:19] or "never",
            Text(one_line(item.get("notes", ""), 60)),
        )
    console.print(table)


@watchlist_app.command("remove")
def watchlist_remove(
    target_id: str = typer.Argument(
        ..., help="ID (or first 8+ characters) or value of the item to remove"
    ),
):
    """Remove an item from the watchlist by ID or target value."""
    if WatchlistService().remove_target(target_id):
        console.print(f"[success]✓ Removed:[/success] [info]{escape(target_id)}[/info]")
    else:
        console.print(
            f"[danger]Watchlist target '{escape(target_id)}' not found.[/danger]"
        )
        raise typer.Exit(code=1)


@watchlist_app.command("check")
def watchlist_check(
    limit: int = typer.Option(
        5, "--limit", "-l", min=1, max=500, help="Matches per target"
    ),
    peek: bool = typer.Option(
        False, "--peek", help="Do not update the 'last checked' timestamp"
    ),
):
    """Check stored CVEs against the watchlist; highlights new matches."""
    res = WatchlistService().check_alerts(limit_per_target=limit, mark_checked=not peek)
    console.print(
        f"[title]Watchlist check:[/title] {res['watchlist_count']} targets, "
        f"[warning]{res['alert_count']} with matches[/warning], "
        f"[info]{res['new_total']} new since last check[/info]\n"
    )
    for alert in res.get("alerts", []):
        item = alert["watchlist_item"]
        header = Text("⚡ ")
        header.append(f"{item['target_type'].upper()} ", style="title")
        header.append(item["target_value"], style="accent")
        header.append(f"  ({alert['match_count']} matches, {alert['new_count']} new)")
        console.print(header)
        new_ids = set(alert.get("new_cve_ids", []))
        for cve in alert["cves"]:
            line = Text("   • ")
            line.append(cve["id"], style="cve.id")
            if cve["id"] in new_ids:
                line.append(" NEW", style="success")
            line.append(f"  {severity_label(cve.get('severity'))}  ")
            line.append(one_line(cve.get("summary", ""), 75))
            console.print(line)
        console.print("")
