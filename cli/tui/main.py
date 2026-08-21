from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Static

from cli.branding import SAGE_GREEN, brand_text
from core.formatter import format_cvss
from core.models import CVEModel
from services.analytics import AnalyticsService
from services.watchlist import WatchlistService
from storage.repositories import CVERepository


class CVEDetailModal(ModalScreen):
    BINDINGS = [Binding("escape", "close_modal", "Close")]

    def __init__(self, cve: CVEModel):
        super().__init__()
        self.cve = cve

    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                "\n".join(
                    [
                        f"ID: {self.cve.id}",
                        (
                            f"Severity: {self.cve.severity or 'N/A'} "
                            f"(CVSS {format_cvss(self.cve.cvss)})"
                        ),
                        f"Vendor: {self.cve.vendor or 'N/A'}",
                        f"Published: {self.cve.published or 'N/A'}",
                        "",
                        self.cve.summary,
                    ]
                )
            ),
            Button("Close", id="close_btn"),
        )

    def action_close_modal(self) -> None:
        self.dismiss()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close_btn":
            self.dismiss()


class DashboardScreen(Screen):
    def compose(self) -> ComposeResult:
        stats = AnalyticsService().get_summary_stats()
        yield Static(
            brand_text(
                "\n".join(
                    [
                        f"Total CVEs: {stats['total_cves']}",
                        f"Critical: {stats['critical']}    High: {stats['high']}",
                        "",
                        "[S] Search    [W] Watchlist    [D] Dashboard    [Q] Quit",
                    ]
                )
            ),
            classes="brand",
        )


class SearchScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Static(brand_text("Search stored CVE records"), classes="brand_header")
        yield Horizontal(
            Input(placeholder="Search", id="search_input"),
            Button("Search", id="search_btn"),
        )
        yield DataTable(id="results_table")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("CVE ID", "Severity", "CVSS", "Vendor", "Summary")
        self.load_results("")

    def load_results(self, query: str) -> None:
        table = self.query_one(DataTable)
        table.clear()
        self.cve_map = {}
        for cve in CVERepository().search(query=query, limit=100):
            table.add_row(
                cve.id,
                cve.severity or "N/A",
                format_cvss(cve.cvss),
                cve.vendor or "N/A",
                cve.summary[:80],
                key=cve.id,
            )
            self.cve_map[cve.id] = cve

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.load_results(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "search_btn":
            self.load_results(self.query_one("#search_input", Input).value)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.app.push_screen(CVEDetailModal(self.cve_map[str(event.row_key.value)]))


class WatchlistScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Static(brand_text("Watchlist"), classes="brand_header")
        yield Horizontal(
            Input(placeholder="Type", id="target_type_input"),
            Input(placeholder="Value", id="target_value_input"),
            Button("Add", id="add_target_btn"),
        )
        yield DataTable(id="watchlist_table")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Type", "Value", "Added At", "Notes")
        self.load_watchlist()

    def load_watchlist(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        for item in WatchlistService().list_targets():
            table.add_row(
                item["target_type"],
                item["target_value"],
                item["created_at"][:19],
                item["notes"],
                key=item["id"],
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "add_target_btn":
            WatchlistService().add_target(
                target_type=self.query_one("#target_type_input", Input).value,
                target_value=self.query_one("#target_value_input", Input).value,
            )
            self.load_watchlist()


class MainApp(App):
    CSS = """
    .brand {
        content-align: center middle;
        color: __SAGE_GREEN__;
        text-style: bold;
        height: 1fr;
    }
    .brand_header {
        content-align: center middle;
        color: __SAGE_GREEN__;
        text-style: bold;
        height: auto;
        padding: 1 0;
    }
    """.replace("__SAGE_GREEN__", SAGE_GREEN)

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("d", "show_dashboard", "Dashboard"),
        Binding("s", "show_search", "Search"),
        Binding("w", "show_watchlist", "Watchlist"),
    ]

    def on_mount(self) -> None:
        from cli.tui.theme import apply_theme

        apply_theme(self)
        self.install_screen(DashboardScreen(), name="dashboard")
        self.install_screen(SearchScreen(), name="search")
        self.install_screen(WatchlistScreen(), name="watchlist")
        self.push_screen("dashboard")

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(id="main_container")
        yield Footer()

    def action_show_dashboard(self) -> None:
        self.switch_screen("dashboard")

    def action_show_search(self) -> None:
        self.switch_screen("search")

    def action_show_watchlist(self) -> None:
        self.switch_screen("watchlist")


if __name__ == "__main__":
    MainApp().run()
