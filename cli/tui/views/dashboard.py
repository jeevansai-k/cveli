"""Dashboard view: brand, headline stats, data-source freshness, key hints."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Static

from cli.branding import brand_text
from cli.tui.views.base import View
from cli.tui.widgets import Notice
from core.safety import AUTHORIZED_USE_DISCLAIMER


class DashboardView(View):
    view_id = "dashboard"
    label = "Dashboard"
    icon = "⌂"

    def compose(self) -> ComposeResult:
        yield Static(
            brand_text("Search-first CVE & vulnerability intelligence"),
            classes="brand",
            markup=False,
        )
        with Horizontal(classes="card-row", id="stat_row"):
            for key, label in (
                ("total_cves", "CVEs stored"),
                ("critical", "◆ Critical"),
                ("high", "▲ High"),
                ("kev", "CISA KEV"),
                ("public_exploits", "With public exploits"),
                ("exploitdb_entries", "Exploit-DB entries"),
            ):
                yield Static(f"{label}\n–", id=f"stat_{key}", classes="stat-card")
        yield Static("Data sources", classes="section-title")
        yield Static("", id="source_rows", markup=False)
        yield Static("Keyboard", classes="section-title")
        yield Static(
            "1-8 switch views · / or Ctrl+F search · Ctrl+P command palette · "
            "Ctrl+T theme · Ctrl+B navigation · F2 intel panel · "
            "Enter open · Esc back · Ctrl+Q quit",
            classes="muted",
            markup=False,
        )
        yield Notice(AUTHORIZED_USE_DISCLAIMER, info=True)

    def on_mount(self) -> None:
        self.refresh_stats()

    def on_show_view(self) -> None:
        self.refresh_stats()

    def refresh_stats(self) -> None:
        from services.analytics import AnalyticsService

        try:
            analytics = AnalyticsService()
            stats = analytics.get_summary_stats()
            sources = analytics.source_status()
        except Exception as error:  # pragma: no cover - defensive
            self.query_one("#source_rows", Static).update(f"Unavailable: {error}")
            return
        labels = {
            "total_cves": "CVEs stored",
            "critical": "◆ Critical",
            "high": "▲ High",
            "kev": "CISA KEV",
            "public_exploits": "With public exploits",
            "exploitdb_entries": "Exploit-DB entries",
        }
        for key, label in labels.items():
            self.query_one(f"#stat_{key}", Static).update(
                f"{label}\n{stats.get(key, 0):,}"
            )
        if not sources:
            text = "No source has been refreshed yet. Run a search or `cveli sync`."
        else:
            text = "\n".join(
                f"{row['source']:<10} {row['status']:<8} "
                f"last success: {row['last_success'] or 'never'}"
                + (f"  rows: {row['row_count']:,}" if row.get("row_count") else "")
                for row in sources
            )
        self.query_one("#source_rows", Static).update(text)
