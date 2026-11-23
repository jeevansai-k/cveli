"""Watchlist view: add/remove targets and check for (new) matches."""

from __future__ import annotations

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Button, DataTable, Input, Select, Static

from cli.tui.views.base import View
from cli.tui.widgets import ConfirmModal, EmptyState, call_safely
from core.text import one_line
from services.watchlist import WatchlistService

TYPES = [("Vendor", "vendor"), ("Product", "product"), ("CWE", "cwe")]


class WatchlistView(View):
    view_id = "watchlist"
    label = "Watchlist"
    icon = "◉"
    BINDINGS = [
        Binding("delete", "remove_selected", "Remove selected", show=True),
        Binding("ctrl+d", "remove_selected", "Remove selected", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield Static("Watchlist", classes="view-title")
        yield Static(
            "Track vendors, products and CWEs. 'Check' lists stored CVEs that "
            "match, marking those that are new since the previous check.",
            classes="view-subtitle",
        )
        with Horizontal(classes="form-row"):
            yield Select(
                TYPES, value="vendor", allow_blank=False, id="target_type_input"
            )
            yield Input(
                placeholder="Value (e.g. OpenSSL, CWE-79)",
                id="target_value_input",
                classes="field",
            )
            yield Input(
                placeholder="Notes (optional)", id="target_notes_input", classes="field"
            )
            yield Button("Add", id="add_target_btn", variant="primary")
            yield Button("Check", id="check_btn")
        with Horizontal(classes="form-row"):
            yield Button(
                "Remove selected",
                id="remove_target_btn",
                variant="error",
                disabled=True,
            )
            yield Static(
                "Select a row, then press 'Remove selected' (or the Delete key).",
                classes="muted",
                markup=False,
            )
        yield DataTable(id="watchlist_table", cursor_type="row")
        yield Static("", id="watch_results", markup=False)

    def on_mount(self) -> None:
        table = self.query_one("#watchlist_table", DataTable)
        table.add_columns("Type", "Value", "Added", "Last check", "Notes")
        self.load_watchlist()

    def on_show_view(self) -> None:
        self.load_watchlist()

    def load_watchlist(self) -> None:
        table = self.query_one("#watchlist_table", DataTable)
        table.clear()
        self.query_one("#remove_target_btn", Button).disabled = True
        for item in WatchlistService().list_targets():
            table.add_row(
                item["target_type"],
                Text(item["target_value"]),
                item["created_at"][:19],
                item.get("last_checked_at", "")[:19] or "never",
                Text(one_line(item.get("notes", ""), 40)),
                key=item["id"],
            )

    @on(Button.Pressed, "#add_target_btn")
    @on(Input.Submitted, "#target_value_input")
    def _add(self) -> None:
        value = self.query_one("#target_value_input", Input)
        target_type = str(self.query_one("#target_type_input", Select).value)
        notes = self.query_one("#target_notes_input", Input).value

        def add() -> None:
            WatchlistService().add_target(
                target_type=target_type, target_value=value.value, notes=notes
            )

        if call_safely(self, add, "Watchlist"):
            self.app.notify(f"Watching {target_type}: {value.value}", timeout=3)
            value.value = ""
            self.load_watchlist()

    def _selected_target(self) -> tuple[str, str] | None:
        table = self.query_one("#watchlist_table", DataTable)
        if not table.row_count:
            return None
        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        if row_key.value is None:
            return None
        row = table.get_row(row_key)
        return str(row_key.value), f"{row[0]} {row[1]}"

    @on(DataTable.RowHighlighted, "#watchlist_table")
    def _row_highlighted(self) -> None:
        self.query_one("#remove_target_btn", Button).disabled = (
            self._selected_target() is None
        )

    @on(Button.Pressed, "#remove_target_btn")
    def action_remove_selected(self) -> None:
        selected = self._selected_target()
        if selected is None:
            self.app.notify("Select a watchlist entry first.", severity="warning")
            return
        target_id, label = selected

        def done(confirmed: bool | None) -> None:
            if confirmed and WatchlistService().remove_target(target_id):
                self.app.notify(f"Removed '{label}' from the watchlist.", timeout=3)
                self.load_watchlist()

        self.app.push_screen(
            ConfirmModal(
                "Remove from watchlist",
                f"Stop watching {label}?",
                "Yes, remove this watchlist entry.",
            ),
            done,
        )

    @on(Button.Pressed, "#check_btn")
    def _check(self) -> None:
        res = WatchlistService().check_alerts()
        output = self.query_one("#watch_results", Static)
        if not res["alerts"]:
            output.update("No stored CVEs match the watchlist yet.")
            return
        lines = [
            f"{res['alert_count']} target(s) with matches · "
            f"{res['new_total']} new since last check"
        ]
        for alert in res["alerts"]:
            item = alert["watchlist_item"]
            lines.append(
                f"\n{item['target_type'].upper()} {item['target_value']} — "
                f"{alert['match_count']} match(es), {alert['new_count']} new"
            )
            new_ids = set(alert["new_cve_ids"])
            for cve in alert["cves"]:
                marker = " NEW" if cve["id"] in new_ids else ""
                lines.append(f"  • {cve['id']}{marker}  {one_line(cve['summary'], 70)}")
        output.update("\n".join(lines))
        self.load_watchlist()

    def empty(self) -> EmptyState:
        return EmptyState("Watchlist is empty", "Add a vendor, product or CWE above.")
