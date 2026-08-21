"""
CLI Stats Command.

Purpose: Display database analytics summary and vulnerability statistics.
Outputs: Rich tables and metrics cards.
Dependencies: typer, rich, services.analytics.
"""

from rich.console import Console
from rich.table import Table

from services.analytics import AnalyticsService

console = Console()


def stats_command():
    """Display vulnerability statistics and database metrics summary."""
    analytics = AnalyticsService()
    stats = analytics.get_summary_stats()

    table = Table(title="cveli Database Statistics Summary", expand=True)
    table.add_column("Metric", style="bold cyan", width=25)
    table.add_column("Count", justify="right", style="bold yellow", width=15)

    table.add_row("Total CVE Records", str(stats.get("total_cves", 0)))
    table.add_row("Critical Severity", str(stats.get("critical", 0)))
    table.add_row("High Severity", str(stats.get("high", 0)))
    table.add_row("Medium Severity", str(stats.get("medium", 0)))
    table.add_row("Low Severity", str(stats.get("low", 0)))
    table.add_row("Known Exploits (KEV)", str(stats.get("exploits_available", 0)))

    console.print(table)
