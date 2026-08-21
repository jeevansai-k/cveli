from datetime import UTC, datetime, timedelta

import typer
from rich.console import Console

from cli.tui.search_browser import SearchBrowserApp
from core.formatter import (
    format_cve_detail_panel,
    format_cve_json,
    format_cve_markdown,
    format_cve_table,
)
from core.models import CVEModel
from storage.cache import cache_get, cache_set
from storage.repositories import CVERepository
from utils.logger import get_logger

console = Console()
log = get_logger(__name__)

CACHE_TTL_SECONDS = 3600
RANGE_DAYS = {
    "1m": 30,
    "3m": 90,
    "6m": 180,
    "9m": 270,
    "1y": 365,
    "2y": 730,
    "3y": 1095,
    "4y": 1460,
    "5y": 1825,
}


def resolve_search_range(value: str) -> tuple[str, tuple[str, str] | None]:
    key = value.strip().lower().replace(" ", "")
    aliases = {
        "1month": "1m",
        "3months": "3m",
        "6months": "6m",
        "9months": "9m",
        "1year": "1y",
        "2years": "2y",
        "3years": "3y",
        "4years": "4y",
        "5years": "5y",
        "complete": "complete",
        "all": "complete",
    }
    key = aliases.get(key, key)
    if key == "complete":
        return key, None
    if key not in RANGE_DAYS:
        raise typer.BadParameter(
            "Use one of: 1m, 3m, 6m, 9m, 1y, 2y, 3y, 4y, 5y, complete"
        )
    end = datetime.now(UTC)
    start = end - timedelta(days=RANGE_DAYS[key])
    return key, (
        start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    )


def search_cache_key(
    query: str,
    severity: str | None,
    min_cvss: float,
    vendor: str | None,
    cwe: str | None,
    exploit_only: bool,
    limit: int,
    range_key: str,
) -> str:
    parts = [
        query,
        severity or "",
        str(min_cvss),
        vendor or "",
        cwe or "",
        str(exploit_only),
        str(limit),
        range_key,
    ]
    return "search:" + "|".join(part.strip().lower() for part in parts)


def resolve_cve_selection(choice: str, result_count: int) -> int | None:
    cleaned = choice.strip().lower()
    if cleaned in {"q", "quit"}:
        return None
    if not cleaned:
        raise ValueError("Enter a result number or q to quit.")
    if not cleaned.isdigit():
        raise ValueError("Enter a valid result number.")
    index = int(cleaned)
    if not 1 <= index <= result_count:
        raise ValueError(f"Enter a number between 1 and {result_count}.")
    return index - 1


def prompt_for_cve_selection(
    results: list[CVEModel], search_console: Console = console
) -> int | None:
    while True:
        try:
            choice = search_console.input(
                f"Select a CVE to view details [1-{len(results)}, q to quit]: "
            )
        except KeyboardInterrupt:
            search_console.print()
            return None
        try:
            return resolve_cve_selection(choice, len(results))
        except ValueError as error:
            search_console.print(f"[yellow]{error}[/yellow]")


def prompt_after_detail(search_console: Console = console) -> bool:
    while True:
        try:
            choice = search_console.input("[Enter] Back to results    [q] Quit: ")
        except KeyboardInterrupt:
            search_console.print()
            return False
        cleaned = choice.strip().lower()
        if cleaned == "":
            return True
        if cleaned in {"q", "quit"}:
            return False
        search_console.print("[yellow]Press Enter to go back or q to quit.[/yellow]")


def run_interactive_search_results(
    results: list[CVEModel], search_console: Console = console
) -> None:
    while True:
        search_console.print(
            format_cve_table(
                results, title=f"CVE Search Results ({len(results)} matches)"
            )
        )
        selection = prompt_for_cve_selection(results, search_console=search_console)
        if selection is None:
            return
        search_console.print()
        search_console.print(format_cve_detail_panel(results[selection]))
        search_console.print()
        if not prompt_after_detail(search_console=search_console):
            return
        search_console.print()


def search_command(
    ctx: typer.Context,
    query: str = typer.Argument(
        "", help="Search query keyword or CVE ID (e.g. 'openssl' or 'CVE-2024-1234')"
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by severity (Critical, High, Medium, Low)",
    ),
    min_cvss: float = typer.Option(
        0.0, "--min-cvss", "-c", help="Minimum CVSS base score threshold (0.0 - 10.0)"
    ),
    vendor: str | None = typer.Option(
        None, "--vendor", "-v", help="Filter by vendor name (e.g. 'OpenSSL', 'Apache')"
    ),
    cwe: str | None = typer.Option(
        None, "--cwe", "-w", help="Filter by CWE ID (e.g. 'CWE-79')"
    ),
    exploit_only: bool = typer.Option(
        False, "--exploits", "-e", help="Show only vulnerabilities with public exploits"
    ),
    limit: int = typer.Option(
        2000, "--limit", "-l", help="Maximum number of results to load"
    ),
    live: bool = typer.Option(
        True,
        "--live/--cache",
        help=(
            "Query live CVE sources before showing results; "
            "use --cache for local data only."
        ),
    ),
    search_range: str = typer.Option(
        "1y",
        "--range",
        "-r",
        help=(
            "Publication range: 1m, 3m, 6m, 9m, 1y, 2y, 3y, "
            "4y, 5y, complete. Default: 1y."
        ),
    ),
    output_format: str = typer.Option(
        "table", "--format", "-f", help="Output format (table, json, markdown, detail)"
    ),
):
    """Search CVE vulnerabilities using live sources, with local cache fallback."""
    range_key, date_range = resolve_search_range(search_range)
    cache_key = search_cache_key(
        query, severity, min_cvss, vendor, cwe, exploit_only, limit, range_key
    )
    repo = CVERepository()
    cached_results = repo.search(
        query=query,
        severity=severity,
        cvss_min=min_cvss,
        vendor=vendor,
        cwe_id=cwe,
        exploit_only=exploit_only,
        limit=limit,
    )
    cached_payload = cache_get(cache_key)
    source = ctx.get_parameter_source("live")
    explicit_live = live and source is not None and source.name == "COMMANDLINE"
    used_query_cache = False
    if live and cached_payload and not explicit_live:
        results = [CVEModel(**item) for item in cached_payload["results"]]
        updated = cached_payload.get("updated", "unknown")
        source_note = f"Source: CACHE | Updated: {updated} | Range: {range_key}"
        live = False
        used_query_cache = True
    else:
        source_note = f"Source: CACHE | Range: {range_key}"

    if live and (query or severity or vendor or cwe or exploit_only):
        from services.sync import SyncService

        with console.status("[cyan]Fetching data...[/cyan]", spinner="dots"):
            sync_res = SyncService(repo=repo).sync_sources(
                sources=["nvd", "cve_org", "cisa_kev", "epss"],
                query=query,
                limit=limit,
                date_range=date_range,
            )
        results = repo.search(
            query=query,
            severity=severity,
            cvss_min=min_cvss,
            vendor=vendor,
            cwe_id=cwe,
            exploit_only=exploit_only,
            limit=limit,
        )
        if sync_res["total_synced"]:
            updated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
            cache_set(
                cache_key,
                {"updated": updated, "results": [item.to_dict() for item in results]},
                expire=CACHE_TTL_SECONDS,
            )
            source_note = (
                "Source: LIVE + CACHE | Sources: NVD, CVE.org, CISA KEV, FIRST EPSS "
                f"| Range: {range_key} | Updated: {updated}"
            )
        elif cached_results:
            console.print(
                "[yellow]Live sources unavailable or returned no fresh records. "
                "Showing cache.[/yellow]"
            )
            source_note = (
                f"Source: CACHE | Live refresh returned no records | Range: {range_key}"
            )
        else:
            console.print("[red]Unable to retrieve live vulnerability data.[/red]")
            source_note = (
                f"Source: LIVE attempted | No matching records | Range: {range_key}"
            )
    elif not used_query_cache:
        results = cached_results

    fmt = output_format.lower().strip()
    if fmt == "table":
        try:
            search_app = SearchBrowserApp(results, source_note=source_note)
            search_app.run()
            if search_app.return_to_main_menu:
                from cli.tui.main import MainApp

                MainApp().run()
        except Exception:
            log.exception("Search TUI failed")
            if results:
                console.print(format_cve_table(results))
            else:
                console.print("[bold red]No matching CVE records found.[/bold red]")
    elif fmt == "json":
        if not results:
            console.print("[bold red]No matching CVE records found.[/bold red]")
            return
        console.print(format_cve_json(results))
    elif fmt in ("markdown", "md"):
        if not results:
            console.print("[bold red]No matching CVE records found.[/bold red]")
            return
        console.print(format_cve_markdown(results))
    elif fmt == "detail":
        if not results:
            console.print("[bold red]No matching CVE records found.[/bold red]")
            return
        for cve in results:
            console.print(format_cve_detail_panel(cve))
    else:
        if not results:
            console.print("[bold red]No matching CVE records found.[/bold red]")
            return
        table = format_cve_table(results)
        console.print(table)
