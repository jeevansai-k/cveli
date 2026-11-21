"""
CLI Export Command.

Purpose: Export stored CVE records to JSON, CSV, Markdown or plain text.
"""

from __future__ import annotations

import typer
from rich.markup import escape

from cli.console import get_console
from core.validator import validate_severity
from services.export import ExportService
from storage.repositories import CVERepository
from utils.errors import AppError, ValidationError

console = get_console()


def export_command(
    query: str = typer.Argument(
        "",
        help="Optional search filter applied to stored CVE data before export.",
    ),
    output: str = typer.Option(
        ...,
        "--output",
        "-o",
        help="Required destination file path, e.g. report.json or reports/high.csv.",
    ),
    export_format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Export format: json, csv, markdown, or txt.",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="Optional severity filter, e.g. Critical, High, Medium, Low.",
    ),
    limit: int = typer.Option(500, "--limit", "-l", help="Max records to export"),
    offline: bool = typer.Option(
        False, "--offline", help="Never contact external feeds"
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Allow writing outside the working, home and temp directories",
    ),
):
    """
    Export stored CVE records to a file.

    Export reads from the local cveli database using the optional query and
    severity filters. If no local records match (and --offline is not set),
    cveli tries the configured external feeds, stores any returned CVEs, then
    exports the matching data.
    """
    if not 1 <= limit <= 100_000:
        raise typer.BadParameter("must be between 1 and 100000", param_hint="--limit")
    if severity:
        try:
            validate_severity(severity)
        except ValidationError as error:
            raise typer.BadParameter(str(error), param_hint="--severity") from error
        severity = severity.strip().capitalize()
    repo = CVERepository()
    cves = repo.search(query=query, severity=severity, limit=limit)

    if not cves and not offline:
        console.print(
            "[warning]No local records found for export. "
            "Fetching from external feeds…[/warning]"
        )
        from services.sync import SyncService

        SyncService(repo=repo).sync_sources(
            sources=["nvd", "cisa_kev"], query=query, limit=limit
        )
        cves = repo.search(query=query, severity=severity, limit=limit)

    if not cves:
        console.print("[danger]No matching CVE records found to export.[/danger]")
        raise typer.Exit(code=1)

    try:
        saved_path = ExportService().export(
            cves, output_path=output, export_format=export_format, allow_outside=force
        )
    except AppError as error:
        console.print(f"[danger]Export failed:[/danger] {escape(str(error))}")
        raise typer.Exit(code=2) from error

    console.print(
        f"[success]✓ Exported {len(cves)} CVE records to:[/success] "
        f"[info]{escape(saved_path)}[/info]"
    )
