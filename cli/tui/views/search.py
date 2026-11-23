"""CVE search view (live + cached) with loading, empty and error states."""

from __future__ import annotations

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Input,
    LoadingIndicator,
    Select,
    Static,
)

from cli.tui.views.base import View
from cli.tui.widgets import EmptyState, ErrorState
from core.formatter import format_cvss, format_epss, severity_label
from core.models import CVEModel
from core.text import one_line

RANGES = [
    ("1 month", "1m"),
    ("6 months", "6m"),
    ("1 year", "1y"),
    ("3 years", "3y"),
    ("5 years", "5y"),
    ("Complete", "complete"),
]


class SearchView(View):
    view_id = "search"
    label = "Search CVEs"
    icon = "⌕"
    BINDINGS = [Binding("p", "add_to_project", "Add to project")]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.results: dict[str, CVEModel] = {}

    def compose(self) -> ComposeResult:
        yield Static("Search CVEs", classes="view-title")
        yield Static(
            "Keyword, vendor/product or exact CVE ID. Live mode queries NVD, "
            "CVE.org, CISA KEV and FIRST EPSS; otherwise only the local cache.",
            classes="view-subtitle",
        )
        with Horizontal(classes="form-row"):
            yield Input(
                placeholder="e.g. openssl or CVE-2021-44228",
                id="cve_query",
                classes="field",
            )
            yield Select(RANGES, value="1y", allow_blank=False, id="cve_range")
            yield Checkbox("Live", value=True, id="cve_live")
            yield Checkbox("KEV only", id="cve_kev")
            yield Button("Search", id="cve_search", variant="primary")
        yield LoadingIndicator(id="cve_loading", classes="-hidden")
        yield Vertical(id="cve_state")
        yield DataTable(id="cve_results", cursor_type="row", zebra_stripes=True)
        yield Static("", id="cve_status", classes="muted", markup=False)

    def on_mount(self) -> None:
        table = self.query_one("#cve_results", DataTable)
        table.add_columns(
            "CVE ID",
            "Severity",
            "CVSS",
            "EPSS",
            "KEV",
            "Exploits",
            "Published",
            "Summary",
        )
        self.run_search("", live=False)

    def focus_primary(self) -> None:
        self.query_one("#cve_query", Input).focus()

    @on(Input.Submitted, "#cve_query")
    @on(Button.Pressed, "#cve_search")
    def _submit(self) -> None:
        self.run_search(
            self.query_one("#cve_query", Input).value,
            live=self.query_one("#cve_live", Checkbox).value,
        )

    def run_search(self, query: str, live: bool = True) -> None:
        self.query_one("#cve_query", Input).value = query
        self.query_one("#cve_loading").remove_class("-hidden")
        self.query_one("#cve_state").remove_children()
        self.query_one("#cve_status", Static).update("Searching…")
        range_value = self.query_one("#cve_range", Select).value
        kev = self.query_one("#cve_kev", Checkbox).value
        self._search_worker(query.strip(), live, str(range_value), bool(kev))

    @work(thread=True, exclusive=True, group="cve-search")
    def _search_worker(self, query: str, live: bool, range_key: str, kev: bool) -> None:
        from cli.commands.search_cmd import is_cve_id, resolve_search_range
        from storage.repositories import CVERepository

        repo = CVERepository()
        errors: dict[str, str] = {}
        _key, date_range = resolve_search_range(range_key)
        if is_cve_id(query):
            query, date_range = query.upper(), None
        since, until = date_range if date_range else (None, None)
        try:
            if live and (query or kev):
                from services.sync import SyncService

                errors = (
                    SyncService(repo=repo)
                    .sync_sources(
                        sources=["nvd", "cve_org", "cisa_kev", "epss"],
                        query=query,
                        limit=500,
                        date_range=date_range,
                    )
                    .get("errors", {})
                )
            results = repo.search(
                query=query,
                kev_only=kev,
                limit=500,
                published_since=since,
                published_until=until,
            )
        except Exception as error:
            self.app.call_from_thread(self._show_error, str(error))
            return
        self.app.call_from_thread(self._show_results, results, errors, live)

    def _show_error(self, message: str) -> None:
        self.query_one("#cve_loading").add_class("-hidden")
        state = self.query_one("#cve_state")
        state.remove_children()
        state.mount(
            ErrorState(
                "Search failed",
                message,
                "Check the database path in Settings or run `cveli doctor`.",
            )
        )
        self.query_one("#cve_status", Static).update("")

    def _show_results(
        self, results: list[CVEModel], errors: dict[str, str], live: bool
    ) -> None:
        self.query_one("#cve_loading").add_class("-hidden")
        table = self.query_one("#cve_results", DataTable)
        table.clear()
        self.results = {cve.id: cve for cve in results}
        state = self.query_one("#cve_state")
        state.remove_children()
        if errors:
            state.mount(
                ErrorState(
                    "Some live sources were unreachable",
                    ", ".join(f"{k}: {v}" for k, v in sorted(errors.items())),
                    "Showing cached data. Retry later or untick Live.",
                )
            )
        if not results:
            state.mount(
                EmptyState(
                    "No CVEs found",
                    "Try a broader keyword, a longer range, or an exact CVE ID.",
                )
            )
        for cve in results:
            table.add_row(
                Text(cve.id, style="bold"),
                severity_label(cve.severity),
                format_cvss(cve.cvss),
                format_epss(cve.epss),
                "YES" if cve.kev else "no",
                str(cve.public_exploit_count) if cve.public_exploit_count else "–",
                cve.published or "N/A",
                one_line(cve.summary, 70),
                key=cve.id,
            )
        mode = "live + cache" if live else "cache"
        self.query_one("#cve_status", Static).update(
            f"{len(results)} result(s) · source: {mode} · Enter opens details"
        )
        if results:
            self.app.show_intel(results[0])  # type: ignore[attr-defined]

    @on(DataTable.RowHighlighted, "#cve_results")
    def _highlight(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is not None and event.row_key.value in self.results:
            self.app.show_intel(self.results[event.row_key.value])  # type: ignore[attr-defined]

    def action_add_to_project(self) -> None:
        table = self.query_one("#cve_results", DataTable)
        if not table.row_count:
            self.app.notify("Search for a CVE first.", severity="warning")
            return
        key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        if key:
            from cli.tui.widgets import add_to_project

            add_to_project(self.app, "cve", str(key), str(key))

    @on(DataTable.RowSelected, "#cve_results")
    def _open(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None:
            return
        cve = self.results.get(str(event.row_key.value))
        if cve:
            from cli.tui.search_browser import DetailScreen

            self.app.push_screen(DetailScreen(cve))
