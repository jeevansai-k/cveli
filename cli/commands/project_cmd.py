"""``cveli project`` — research workspaces."""

from __future__ import annotations

import typer
from rich.table import Table
from rich.text import Text

from cli.commands.common import check_format, console, emit_json, guard
from services.projects import ProjectService

project_app = typer.Typer(
    help="Research projects: group CVEs, exploit references, saved dorks, reports.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)


@project_app.command("create")
def create(
    name: str = typer.Argument(..., help="Project name"),
    notes: str = typer.Option("", "--notes", "-n"),
):
    """Create a research project."""
    project = guard(lambda: ProjectService().create(name, notes))
    console.print(f"[success]✓ Created project[/success] {project['id'][:8]}")


@project_app.command("list")
def list_projects(
    output_format: str = typer.Option("table", "--format", "-f", help="table|json"),
):
    """List research projects."""
    fmt = check_format(output_format, ("table", "json"))
    projects = ProjectService().list()
    if fmt == "json":
        emit_json(projects)
        return
    if not projects:
        console.print("[muted]No projects yet: cveli project create <name>[/muted]")
        return
    table = Table(title="Research projects", expand=True)
    for column in ("ID", "Name", "Items", "Dorks", "Created"):
        table.add_column(column)
    for p in projects:
        table.add_row(
            p["id"][:8],
            Text(p["name"]),
            str(p["item_count"]),
            str(p["dork_count"]),
            p["created_at"],
        )
    console.print(table)


@project_app.command("show")
def show(
    ref: str = typer.Argument(..., help="Project ID or name"),
    output_format: str = typer.Option("table", "--format", "-f", help="table|json"),
):
    """Show a project's items and saved dorks."""
    fmt = check_format(output_format, ("table", "json"))
    project = guard(lambda: ProjectService().show(ref))
    if fmt == "json":
        emit_json(project)
        return
    console.print(Text(f"{project['name']}  ({project['id'][:8]})", style="title"))
    for item in project["items"]:
        console.print(Text(f"  • {item['kind']}: {item['ref_id']}  {item['note']}"))
    for dork in project["dorks"]:
        console.print(Text(f"  • dork [{dork['risk_level']}]: {dork['query']}"))
    if not project["items"] and not project["dorks"]:
        console.print("[muted]  (empty)[/muted]")


@project_app.command("add")
def add(
    ref: str = typer.Argument(..., help="Project ID or name"),
    kind: str = typer.Argument(..., help="cve | exploit"),
    item_id: str = typer.Argument(..., help="CVE-ID or EDB-ID"),
    note: str = typer.Option("", "--note", "-n"),
):
    """Add a CVE or Exploit-DB reference to a project."""
    guard(lambda: ProjectService().add(ref, kind.lower(), item_id, note))
    console.print("[success]✓ Added[/success]")


@project_app.command("delete")
def delete(
    ref: str = typer.Argument(..., help="Project ID or name"),
    yes: bool = typer.Option(False, "--yes", "-y"),
):
    """Delete a project and its saved dorks."""
    if not yes and not typer.confirm(f"Delete project '{ref}'?"):
        raise typer.Exit(code=1)
    if ProjectService().delete(ref):
        console.print("[success]✓ Deleted[/success]")
    else:
        console.print("[danger]Project not found[/danger]")
        raise typer.Exit(code=1)
