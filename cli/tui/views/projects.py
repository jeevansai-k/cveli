"""Research projects view: saved CVEs, exploit references, dorks and reports."""

from __future__ import annotations

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Button, DataTable, Input, Static

from cli.tui.views.base import View
from cli.tui.widgets import ConfirmModal, call_safely
from services.projects import ProjectService


class ProjectsView(View):
    view_id = "projects"
    label = "Projects"
    icon = "▤"
    BINDINGS = [Binding("delete", "delete_project", "Delete project")]

    def compose(self) -> ComposeResult:
        yield Static("Research projects", classes="view-title")
        yield Static(
            "Projects are the only place CVELI stores usernames, domains and dorks "
            "— and only when you save them. Delete a project to erase its data.",
            classes="view-subtitle",
        )
        with Horizontal(classes="form-row"):
            yield Input(
                placeholder="New project name", id="project_name", classes="field"
            )
            yield Button("Create", id="project_create", variant="primary")
        yield DataTable(id="project_table", cursor_type="row")
        yield Static("", id="project_detail", markup=False)

    def on_mount(self) -> None:
        self.query_one("#project_table", DataTable).add_columns(
            "Name", "Items", "Dorks", "Created"
        )
        self.load()

    def on_show_view(self) -> None:
        self.load()

    def load(self) -> None:
        table = self.query_one("#project_table", DataTable)
        table.clear()
        for project in ProjectService().list():
            table.add_row(
                Text(project["name"]),
                str(project["item_count"]),
                str(project["dork_count"]),
                project["created_at"],
                key=project["id"],
            )

    @on(Button.Pressed, "#project_create")
    @on(Input.Submitted, "#project_name")
    def _create(self) -> None:
        name = self.query_one("#project_name", Input)
        if call_safely(self, lambda: ProjectService().create(name.value), "Projects"):
            name.value = ""
            self.load()

    @on(DataTable.RowHighlighted, "#project_table")
    def _show(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None:
            return
        project = ProjectService().show(str(event.row_key.value))
        lines = [f"{project['name']} — {project['notes'] or 'no notes'}"]
        lines += [
            f"  • {i['kind']}: {i['ref_id']} {i['note']}" for i in project["items"]
        ]
        lines += [
            f"  • dork [{d['risk_level']}] {d['query']}" for d in project["dorks"]
        ]
        if len(lines) == 1:
            lines.append("  (empty)")
        self.query_one("#project_detail", Static).update("\n".join(lines))

    def action_delete_project(self) -> None:
        table = self.query_one("#project_table", DataTable)
        if not table.row_count:
            return
        key = str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)

        def done(confirmed: bool | None) -> None:
            if confirmed and ProjectService().delete(key):
                self.app.notify("Project deleted.")
                self.query_one("#project_detail", Static).update("")
                self.load()

        self.app.push_screen(
            ConfirmModal(
                "Delete project",
                "Deletes the project, its saved dorks and item links.",
                "I want to permanently delete this project.",
            ),
            done,
        )
