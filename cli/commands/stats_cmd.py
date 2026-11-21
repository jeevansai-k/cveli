"""
CLI Stats Command.

Purpose: Display database analytics summary, source freshness and cache metrics.
"""

from __future__ import annotations

from rich.table import Table

from cli.console import get_console
from services.analytics import AnalyticsService
from storage.cache import cache_stats

console = get_console()


def stats_command():
    """Display vulnerability statistics and database metrics summary."""
    analytics = AnalyticsService()
    stats = analytics.get_summary_stats()

    table = Table(title="cveli Database Statistics", expand=True, border_style="dim")
    table.add_column("Metric", style="title", width=28)
    table.add_column("Count", justify="right", style="accent", width=15)

    table.add_row("Total CVE Records", str(stats.get("total_cves", 0)))
    table.add_row("◆ Critical Severity", str(stats.get("critical", 0)))
    table.add_row("▲ High Severity", str(stats.get("high", 0)))
    table.add_row("● Medium Severity", str(stats.get("medium", 0)))
    table.add_row("▽ Low Severity", str(stats.get("low", 0)))
    table.add_row("– Not yet scored", str(stats.get("unscored", 0)))
    table.add_row("CISA KEV (known exploited)", str(stats.get("kev", 0)))
    table.add_row("With public exploit refs", str(stats.get("public_exploits", 0)))
    table.add_row("Exploit-DB entries indexed", str(stats.get("exploitdb_entries", 0)))
    console.print(table)

    cache = cache_stats()
    if "entries" in cache:
        console.print(
            f"[muted]Cache: {cache['entries']} entries, "
            f"{cache['size_bytes'] / 1_048_576:.1f} MB of "
            f"{cache['size_limit_bytes'] / 1_048_576:.0f} MB[/muted]"
        )
    for source in analytics.source_status():
        last = source["last_success"] or "never"
        console.print(
            f"[muted]{source['source']}: {source['status']} · "
            f"last success {last}[/muted]"
        )
