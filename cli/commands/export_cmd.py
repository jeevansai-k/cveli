"""
CLI Export Command.

Purpose: Export CVE query results to disk files in JSON, CSV, Markdown, or Plain Text.
Inputs: Search query, export format, output file path.
Outputs: Written file on disk.
Responsibilities: Perform database query and delegate to ExportService.
Dependencies: typer, rich, storage.repositories, services.export.
"""

import typer
from rich.console import Console

from services.export import ExportService
from storage.repositories import CVERepository

console = Console()


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
):
    """
    Export stored CVE records to a file.

    Export reads from the local cveli database using the optional query and
    severity filters. If no local records match, cveli tries the configured
    external feeds, stores any returned CVEs, then exports the matching data.

    Examples:

        cveli export openssl --output openssl.json --format json
        cveli export fortinet --output fortinet.csv --format csv
        cveli export --severity High --output high.md --format markdown
        cveli export http --output http.txt --format txt
    """
    repo = CVERepository()
    cves = repo.search(query=query, severity=severity, limit=limit)

    if not cves:
        console.print(
            "[yellow]No local records found for export. "
            "Fetching from external feeds...[/yellow]"
        )
        from services.sync import SyncService

        sync_svc = SyncService(repo=repo)
        sync_svc.sync_sources(sources=["nvd", "cisa_kev"], query=query, limit=limit)
        cves = repo.search(query=query, severity=severity, limit=limit)

    if not cves:
        console.print("[bold red]No matching CVE records found to export.[/bold red]")
        return

    exporter = ExportService()
    saved_path = exporter.export(cves, output_path=output, export_format=export_format)

    console.print(
        f"[bold green]✓ Successfully exported {len(cves)} CVE records to:[/bold green] "
        f"[cyan]{saved_path}[/cyan]"
    )
