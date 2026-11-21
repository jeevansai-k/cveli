"""
CLI Search Command.

Live-first CVE search with local cache fallback.
Fixes: B5 (``--range`` now filters locally stored results too), B10 (input
validation), B11 (no TUI when stdout/stdin are not terminals), B12 (``--kev``
and ``--public-exploit`` replace the ambiguous ``--exploits``), B16 (cache key
covers every filter).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import typer
from rich.console import Console

from cli.console import get_console, get_err_console, is_interactive
from cli.tui.search_browser import SearchBrowserApp
from core.formatter import (
    format_cve_detail_panel,
    format_cve_json,
    format_cve_markdown,
    format_cve_table,
)
from core.models import CVEModel
from core.validator import validate_cwe_id, validate_severity
from services.metrics import record_metric
from storage.cache import cache_get, cache_set
from storage.repositories import CVERepository
from utils.errors import ValidationError
from utils.logger import get_logger

console = get_console()
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
SORT_CHOICES = ("published", "cvss", "epss", "updated", "id")
FORMAT_CHOICES = ("table", "json", "markdown", "md", "detail", "plain")


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
    kev_only: bool = False,
    public_exploit_only: bool = False,
    sort: str = "published",
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
        str(kev_only),
        str(public_exploit_only),
        sort,
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
        except (KeyboardInterrupt, EOFError):
            search_console.print()
            return None
        try:
            return resolve_cve_selection(choice, len(results))
        except ValueError as error:
            search_console.print(f"[warning]{error}[/warning]")


def prompt_after_detail(search_console: Console = console) -> bool:
    while True:
        try:
            choice = search_console.input("[Enter] Back to results    [q] Quit: ")
        except (KeyboardInterrupt, EOFError):
            search_console.print()
            return False
        cleaned = choice.strip().lower()
        if cleaned == "":
            return True
        if cleaned in {"q", "quit"}:
            return False
        search_console.print("[warning]Press Enter to go back or q to quit.[/warning]")


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


def _normalize_severity(severity: str | None) -> str | None:
    if not severity:
        return None
    try:
        validate_severity(severity)
    except ValidationError as error:
        raise typer.BadParameter(str(error), param_hint="--severity") from error
    return severity.strip().capitalize()


def _normalize_cwe(cwe: str | None) -> str | None:
    if not cwe:
        return None
    value = cwe.strip().upper()
    if value.isdigit():
        value = f"CWE-{value}"
    try:
        validate_cwe_id(value)
    except ValidationError as error:
        raise typer.BadParameter(str(error), param_hint="--cwe") from error
    return value


def _exploits_for(results: list[CVEModel]) -> dict[str, list]:
    try:
        from services.exploitdb import ExploitDBService

        service = ExploitDBService()
        return {cve.id: service.for_cve(cve.id) for cve in results}
    except Exception as error:
        log.debug(f"Exploit lookup skipped: {error}")
        return {}


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
        0.0,
        "--min-cvss",
        "-c",
        min=0.0,
        max=10.0,
        help="Minimum CVSS base score threshold (0.0 - 10.0)",
    ),
    vendor: str | None = typer.Option(
        None, "--vendor", "-v", help="Filter by vendor name (e.g. 'OpenSSL', 'Apache')"
    ),
    cwe: str | None = typer.Option(
        None, "--cwe", "-w", help="Filter by CWE ID (e.g. 'CWE-79')"
    ),
    kev_only: bool = typer.Option(
        False, "--kev", "-k", help="Only CVEs listed in CISA Known Exploited (KEV)"
    ),
    public_exploit_only: bool = typer.Option(
        False,
        "--public-exploit",
        "-p",
        help="Only CVEs with public Exploit-DB references",
    ),
    exploit_only: bool = typer.Option(
        False,
        "--exploits",
        "-e",
        help="Deprecated alias for --kev",
        hidden=True,
    ),
    limit: int = typer.Option(
        2000, "--limit", "-l", min=1, max=20000, help="Maximum number of results"
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
            "Publication range: 1m, 3m, 6m, 9m, 1y, 2y, 3y, 4y, 5y, complete. "
            "Default: 1y."
        ),
    ),
    sort: str = typer.Option(
        "published", "--sort", help=f"Sort by: {', '.join(SORT_CHOICES)}"
    ),
    output_format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format (table, json, markdown, detail, plain)",
    ),
):
    """Search CVE vulnerabilities using live sources, with local cache fallback."""
    severity = _normalize_severity(severity)
    cwe = _normalize_cwe(cwe)
    if exploit_only:
        get_err_console().print(
            "[warning]--exploits is deprecated; using --kev.[/warning]"
        )
        kev_only = True
    if sort not in SORT_CHOICES:
        raise typer.BadParameter(
            f"Use one of: {', '.join(SORT_CHOICES)}", param_hint="--sort"
        )
    fmt = output_format.lower().strip()
    if fmt not in FORMAT_CHOICES:
        raise typer.BadParameter(
            f"Use one of: {', '.join(FORMAT_CHOICES)}", param_hint="--format"
        )

    range_key, date_range = resolve_search_range(search_range)
    cache_key = search_cache_key(
        query,
        severity,
        min_cvss,
        vendor,
        cwe,
        False,
        limit,
        range_key,
        kev_only,
        public_exploit_only,
        sort,
    )
    since, until = date_range if date_range else (None, None)
    filters = {
        "query": query,
        "severity": severity,
        "cvss_min": min_cvss,
        "vendor": vendor,
        "cwe_id": cwe,
        "kev_only": kev_only,
        "public_exploit_only": public_exploit_only,
        "limit": limit,
        "sort_by": sort,
        "published_since": since,
        "published_until": until,
    }
    started = datetime.now(UTC)
    repo = CVERepository()
    cached_results = repo.search(**filters)
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

    if live and (query or severity or vendor or cwe or kev_only or public_exploit_only):
        from services.sync import SyncService

        with console.status("[info]Fetching live data…[/info]", spinner="dots"):
            sync_res = SyncService(repo=repo).sync_sources(
                sources=["nvd", "cve_org", "cisa_kev", "epss"],
                query=query,
                limit=limit,
                date_range=date_range,
            )
        results = repo.search(**filters)
        updated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        if sync_res["total_synced"]:
            if results:
                cache_set(
                    cache_key,
                    {
                        "updated": updated,
                        "results": [item.to_dict() for item in results],
                    },
                    expire=CACHE_TTL_SECONDS,
                )
            source_note = (
                "Source: LIVE + CACHE | Sources: NVD, CVE.org, CISA KEV, FIRST EPSS "
                f"| Range: {range_key} | Updated: {updated}"
            )
        elif cached_results:
            get_err_console().print(
                "[warning]Live sources unavailable or returned no fresh records. "
                "Showing cached data.[/warning]"
            )
            source_note = (
                f"Source: CACHE | Live refresh returned no records | Range: {range_key}"
            )
        else:
            errors = sync_res.get("errors") or {}
            if errors:
                console.print(
                    "[danger]Unable to reach: "
                    f"{', '.join(sorted(errors))}. "
                    "Check your network or try --cache.[/danger]"
                )
            source_note = (
                f"Source: LIVE attempted | No matching records | Range: {range_key}"
            )
    elif not used_query_cache:
        results = cached_results

    record_metric(
        "search.latency_ms",
        (datetime.now(UTC) - started).total_seconds() * 1000,
        outcome="hit" if results else "empty",
    )

    if fmt == "table" and is_interactive():
        try:
            search_app = SearchBrowserApp(results, source_note=source_note)
            search_app.run()
            if search_app.return_to_main_menu:
                from cli.tui.app import CveliApp

                CveliApp().run()
            return
        except Exception:
            log.exception("Search TUI failed")
            fmt = "plain"

    if not results:
        console.print("[danger]No matching CVE records found.[/danger]")
        console.print(f"[muted]{source_note}[/muted]")
        return
    if fmt == "json":
        if is_interactive():
            console.print_json(format_cve_json(results))
        else:
            print(format_cve_json(results))
    elif fmt in ("markdown", "md"):
        print(format_cve_markdown(results))
    elif fmt == "detail":
        exploits = _exploits_for(results)
        for cve in results:
            console.print(format_cve_detail_panel(cve, exploits=exploits.get(cve.id)))
    else:
        console.print(
            format_cve_table(results, title=f"CVE Search Results ({len(results)})")
        )
        console.print(f"[muted]{source_note}[/muted]")
