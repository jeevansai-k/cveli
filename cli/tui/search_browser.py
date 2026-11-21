from __future__ import annotations

from dataclasses import dataclass
from math import ceil

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.events import Key
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import DataTable, Header, Link, Static

from cli.tui.theme import apply_theme
from core.formatter import (
    build_reference_items,
    format_cvss,
    format_epss,
    severity_label,
)
from core.models import CVEModel, ExploitModel
from core.safety import EXPLOIT_NOTICE, EXPLOITDB_ATTRIBUTION
from core.text import one_line, sanitize_terminal_text

PAGE_SIZE = 25


@dataclass
class PagedResults:
    results: list[CVEModel]
    page_size: int = PAGE_SIZE
    current_page: int = 0

    @property
    def total_results(self) -> int:
        return len(self.results)

    @property
    def total_pages(self) -> int:
        return max(1, ceil(self.total_results / self.page_size))

    @property
    def page_start(self) -> int:
        return self.current_page * self.page_size

    @property
    def page_end(self) -> int:
        return min(self.page_start + self.page_size, self.total_results)

    def page_items(self) -> list[CVEModel]:
        return self.results[self.page_start : self.page_end]

    def page_range_label(self) -> str:
        if not self.results:
            return "Showing 0 of 0 results"
        return (
            f"Showing {self.page_start + 1}-{self.page_end} "
            f"of {self.total_results} results"
        )

    def page_title(self) -> str:
        return f"Page {self.current_page + 1} / {self.total_pages}"

    def next_page(self) -> None:
        if self.current_page < self.total_pages - 1:
            self.current_page += 1

    def previous_page(self) -> None:
        if self.current_page > 0:
            self.current_page -= 1

    def page_serials(self) -> list[int]:
        return list(range(self.page_start + 1, self.page_end + 1))

    def select(self, serial: int) -> CVEModel:
        if not 1 <= serial <= self.total_results:
            raise ValueError(f"Enter a number between 1 and {self.total_results}.")
        return self.results[serial - 1]


def resolve_page_selection(
    choice: str, first_serial: int, last_serial: int
) -> int | None:
    cleaned = choice.strip().lower()
    if cleaned in {"q", "quit"}:
        return None
    if not cleaned:
        raise ValueError("Enter a result number or q to quit.")
    if not cleaned.isdigit():
        raise ValueError("Enter a valid result number.")
    serial = int(cleaned)
    if not first_serial <= serial <= last_serial:
        raise ValueError(f"Enter a number between {first_serial} and {last_serial}.")
    return serial


class SearchResultsScreen(Screen):
    BINDINGS = [
        Binding("alt+left", "previous_page", "Previous", key_display="Alt+Left"),
        Binding("alt+right", "next_page", "Next", key_display="Alt+Right"),
        Binding("q", "quit", "Quit", key_display="Q"),
    ]

    selection_buffer: reactive[str] = reactive("")

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static(id="search_title")
        yield Static(id="search_summary")
        yield Static(id="source_note")
        yield Static(id="empty_state")
        yield DataTable(id="results_table")
        yield Static(id="selection_input")
        yield Static(
            "[Alt+Left] Previous    [Alt+Right] Next    [Enter] Select    [Q] Quit",
            id="search_help",
            markup=False,
        )
        yield Static("", id="search_message")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns(
            "#",
            "CVE ID",
            "Severity",
            "CVSS",
            "EPSS",
            "KEV",
            "Vendor",
            "Published",
            "Summary",
        )
        self.refresh_table()

    def refresh_table(self) -> None:
        pager = self.app.pager
        table = self.query_one(DataTable)
        empty_state = self.query_one("#empty_state", Static)
        table.clear()
        self.page_items = pager.page_items()
        self.query_one("#search_title", Static).update(
            f"CVE Search Results\n{pager.page_title()}"
        )
        self.query_one("#search_summary", Static).update(pager.page_range_label())
        self.query_one("#source_note", Static).update(
            Text(sanitize_terminal_text(self.app.source_note))
        )
        self.query_one("#search_message", Static).update("")

        if not pager.total_results:
            table.display = False
            empty_state.display = True
            empty_state.update(
                "No CVEs Found\n\n"
                "No vulnerabilities matched your search.\n"
                "Try a broader keyword or CVE ID."
            )
            self.query_one("#selection_input", Static).update(
                "[Enter] Back    [Q] Quit"
            )
            return

        table.display = True
        empty_state.display = False
        for serial, cve in zip(pager.page_serials(), self.page_items, strict=True):
            table.add_row(
                Text(str(serial), style="bold"),
                Text(cve.id, style="bold"),
                Text(severity_label(cve.severity)),
                Text(format_cvss(cve.cvss)),
                Text(format_epss(cve.epss)),
                "YES" if cve.kev else "no",
                Text(one_line(cve.vendor or "N/A", 20)),
                cve.published or "N/A",
                Text(one_line(cve.summary, 80)),
                key=str(serial),
            )
        self._update_selection_input()
        if self.page_items:
            table.move_cursor(row=0, column=0)
            table.focus()

    def action_next_page(self) -> None:
        self.app.pager.next_page()
        self.refresh_table()

    def action_previous_page(self) -> None:
        self.app.pager.previous_page()
        self.refresh_table()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key is None:
            return
        self.open_serial(int(str(event.row_key.value)))

    def on_key(self, event: Key) -> None:
        if event.key.lower() == "q":
            self.app.exit()
            event.stop()
            return
        if not self.page_items and event.key == "enter":
            self.app.exit()
            event.stop()
            return
        if event.key.isdigit() and len(self.selection_buffer) < len(
            str(self.app.pager.total_results)
        ):
            self.selection_buffer += event.key
            self._update_selection_input()
            event.stop()
            return
        if event.key == "backspace" and self.selection_buffer:
            self.selection_buffer = self.selection_buffer[:-1]
            self._update_selection_input()
            event.stop()
            return
        if event.key == "enter":
            self._open_from_buffer()
            event.stop()

    def _open_from_buffer(self) -> None:
        if not self.selection_buffer:
            self.open_highlighted_row()
            return
        try:
            serial = resolve_page_selection(
                self.selection_buffer,
                self.app.pager.page_start + 1,
                self.app.pager.page_end,
            )
        except ValueError as error:
            self.query_one("#search_message", Static).update(str(error))
            return
        finally:
            self.selection_buffer = ""
            self._update_selection_input()
        if serial is None:
            self.app.exit()
            return
        self.open_serial(serial)

    def _update_selection_input(self) -> None:
        pager = self.app.pager
        self.query_one("#selection_input", Static).update(
            f"Select CVE # [{pager.page_start + 1}-{pager.page_end}]: "
            f"{self.selection_buffer or '_'}"
        )

    def open_highlighted_row(self) -> None:
        table = self.query_one(DataTable)
        if not table.row_count:
            return
        cell_key = table.coordinate_to_cell_key(table.cursor_coordinate)
        self.open_serial(int(str(cell_key.row_key.value)))

    def open_serial(self, serial: int) -> None:
        try:
            cve = self.app.pager.select(serial)
        except ValueError as error:
            self.query_one("#search_message", Static).update(str(error))
            return
        self.app.push_screen(DetailScreen(cve))


class DetailScreen(Screen):
    BINDINGS = [
        Binding("enter", "back", "Back", key_display="Enter"),
        Binding("escape", "back", "Back", key_display="Esc"),
        Binding("q", "quit", "Quit", key_display="Q"),
    ]

    def __init__(
        self, cve: CVEModel, exploits: list[ExploitModel] | None = None
    ) -> None:
        super().__init__()
        self.cve = cve
        self.exploits = exploits if exploits is not None else self._lookup(cve.id)

    @staticmethod
    def _lookup(cve_id: str) -> list[ExploitModel]:
        try:
            from storage.exploit_repository import ExploitRepository

            return ExploitRepository().for_cve(cve_id)
        except Exception:
            return []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Container(
            Static(
                Text(
                    f"{self.cve.id}    {severity_label(self.cve.severity)}    "
                    f"CVSS {format_cvss(self.cve.cvss)}"
                ),
                classes="detail_header",
            ),
            Horizontal(
                self._metadata_column(),
                self._risk_column(),
                classes="detail_top",
            ),
            self._section(
                "Description",
                Static(Text(sanitize_terminal_text(self.cve.summary) or "N/A")),
            ),
            self._section("Affected Products", self._products_widget()),
            self._section(
                f"Public exploit references ({len(self.exploits)})",
                self._exploits_widget(),
            ),
            self._section("References", self._references_widget()),
            self._section("Sources", Static(self._source_text())),
            Static(
                "[Enter/Esc] Back    [M] Research template    [Q] Quit",
                classes="detail_help",
                markup=False,
            ),
            classes="detail_shell",
        )

    def _metadata_column(self) -> Vertical:
        cwe = "N/A"
        if self.cve.cwe:
            cwe = f"CWE-{self.cve.cwe.id}: {self.cve.cwe.name}"
        column = Vertical(
            Static("Vulnerability", classes="section_title"),
            Static(Text(f"Vendor: {one_line(self.cve.vendor or 'N/A')}")),
            Static(f"Published: {self.cve.published or 'N/A'}"),
            Static(f"Modified: {self.cve.updated or 'N/A'}"),
            Static(Text(f"CWE: {cwe}")),
            classes="detail_column",
        )
        return column

    def _risk_column(self) -> Vertical:
        kev = "YES" if self.cve.kev else "NO"
        column = Vertical(
            Static("Risk", classes="section_title"),
            Static(f"CVSS: {format_cvss(self.cve.cvss)}"),
            Static(Text(f"Vector: {self.cve.vector or 'N/A'}")),
            Static(f"EPSS: {format_epss(self.cve.epss)}"),
            Static(f"EPSS Percentile: {format_epss(self.cve.epss_percentile)}"),
            Static(f"KEV: {kev}"),
            Static(f"KEV Date: {self.cve.kev_date or 'N/A'}"),
            classes="detail_column",
        )
        return column

    def _products_widget(self) -> Static | Vertical:
        if not self.cve.affected_products:
            return Static("N/A")
        products = Vertical(
            *[
                Static(Text(one_line(self._format_product(product))))
                for product in self.cve.affected_products
            ],
            classes="detail_products",
        )
        return products

    def _references_widget(self) -> Vertical:
        items = build_reference_items(self.cve)
        if not items:
            return Vertical(Static("N/A"), classes="detail_references")
        return Vertical(
            *[
                Horizontal(Static(label), Link(url, url=url), classes="reference_row")
                for label, url in items
            ],
            classes="detail_references",
        )

    def _exploits_widget(self) -> Vertical:
        if not self.exploits:
            return Vertical(
                Static(
                    "None indexed. Refresh Exploit-DB in the shell or run "
                    "`cveli exploits refresh`.",
                    markup=False,
                ),
                classes="detail_references",
            )
        rows: list = []
        for exploit in self.exploits:
            rows.append(
                Static(
                    Text(
                        f"EDB-{exploit.edb_id} · {exploit.date_published or 'N/A'} · "
                        f"{exploit.platform or 'N/A'} · {exploit.type or 'N/A'} · "
                        f"{'verified' if exploit.verified else 'unverified'} · "
                        f"{one_line(exploit.author or 'N/A', 30)}\n"
                        f"  {one_line(exploit.title, 100)}"
                    )
                )
            )
            rows.append(
                Horizontal(
                    Static("  Source"),
                    Link(exploit.source_url, url=exploit.source_url),
                    classes="reference_row",
                )
            )
        rows.append(Static(Text(EXPLOIT_NOTICE), classes="muted"))
        rows.append(Static(Text(EXPLOITDB_ATTRIBUTION), classes="muted"))
        return Vertical(*rows, classes="detail_references")

    def _source_text(self) -> str:
        sources = " • ".join(self.cve.sources) if self.cve.sources else "N/A"
        cached = f"\nCached: {self.cve.fetched_at}" if self.cve.fetched_at else ""
        return f"{sources}{cached}"

    def _section(self, title: str, body) -> Vertical:
        return Vertical(
            Static(title, classes="section_title"), body, classes="detail_section"
        )

    def _format_product(self, product: dict | str) -> str:
        name = product.get("name") if isinstance(product, dict) else str(product)
        version = product.get("version", "") if isinstance(product, dict) else ""
        return f"{name} {version}".rstrip()

    def on_key(self, event: Key) -> None:
        if event.key.lower() == "q":
            self.action_quit()
            event.stop()
            return
        if event.key.lower() == "m":
            self.action_template()
            event.stop()
            return
        if event.key in {"enter", "escape"}:
            self.action_back()
            event.stop()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_template(self) -> None:
        from config.settings import get_settings

        if not get_settings().feature_msf:
            self.app.notify("Template generator is disabled.", severity="warning")
            return
        try:
            from cli.tui.views.templates import TemplateScreen
        except ImportError:  # pragma: no cover
            return
        self.app.push_screen(TemplateScreen(cve_id=self.cve.id))

    def action_quit(self) -> None:
        if getattr(self.app, "is_shell", False):
            self.app.pop_screen()
            return
        self.app.return_to_main_menu = True
        self.app.exit()


class SearchBrowserApp(App[None]):
    CSS_PATH = "cveli.tcss"

    BINDINGS = [Binding("ctrl+c", "quit", "Quit", show=False)]

    current_page: reactive[int] = reactive(0)

    def __init__(
        self, results: list[CVEModel], source_note: str = "Source: CACHE"
    ) -> None:
        super().__init__()
        apply_theme(self)
        self.pager = PagedResults(results)
        self.source_note = source_note
        self.return_to_main_menu = False

    def on_mount(self) -> None:
        self.push_screen(SearchResultsScreen())
