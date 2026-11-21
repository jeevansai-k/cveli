"""``cveli doctor`` — environment and data-source diagnostics."""

from __future__ import annotations

import sqlite3

import typer
from rich.table import Table
from rich.text import Text

from cli.commands.common import console, emit_json
from config.settings import get_settings
from config.version import __version__


def collect() -> dict:
    from services.analytics import AnalyticsService
    from storage.cache import cache_stats
    from storage.database import get_engine
    from storage.migrations import LATEST_VERSION, current_version, fts5_available
    from storage.system_repositories import MetricsRepository

    settings = get_settings()
    engine = get_engine()
    with engine.connect() as conn:
        schema = current_version(conn)
        fts = fts5_available(conn)
    analytics = AnalyticsService()
    return {
        "version": __version__,
        "sqlite": sqlite3.sqlite_version,
        "schema_version": schema,
        "schema_latest": LATEST_VERSION,
        "fts5": fts,
        "settings": settings.redacted(),
        "sources": analytics.source_status(),
        "stats": analytics.get_summary_stats(),
        "cache": cache_stats(),
        "metrics": MetricsRepository().summary(),
    }


def doctor_command(
    as_json: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Diagnose settings, paths, schema, data-source freshness and local metrics."""
    data = collect()
    if as_json:
        emit_json(data)
        return
    ok = data["schema_version"] == data["schema_latest"]
    schema_mark = "[success]✓[/success]" if ok else "[danger]✗ outdated[/danger]"
    console.print(
        f"[title]CVELI {data['version']}[/title] · SQLite {data['sqlite']} · "
        f"schema {data['schema_version']}/{data['schema_latest']} {schema_mark}"
        f" · FTS5 {'✓' if data['fts5'] else '✗ (LIKE fallback)'}"
    )
    table = Table(title="Settings (secrets masked)", expand=True)
    table.add_column("Key", style="title")
    table.add_column("Value")
    for key in (
        "db_path",
        "cache_dir",
        "log_dir",
        "nvd_api_key",
        "feature_exploitdb",
        "feature_dorks",
        "feature_msf",
        "metrics_enabled",
        "loaded_env_files",
    ):
        table.add_row(key, Text(data["settings"].get(key, "")))
    console.print(table)
    sources = Table(title="Data sources", expand=True)
    for column in ("Source", "Status", "Last success", "Rows", "Error"):
        sources.add_column(column)
    for row in data["sources"]:
        sources.add_row(
            row["source"],
            row["status"],
            str(row["last_success"] or "never"),
            str(row["row_count"]),
            Text(row["error"][:60]),
        )
    console.print(sources)
    if data["metrics"]:
        metrics = Table(title="Local metrics (30 days)", expand=True)
        for column in ("Metric", "Count", "Avg", "Max"):
            metrics.add_column(column)
        for m in data["metrics"]:
            metrics.add_row(
                m["name"], str(m["count"]), f"{m['avg']:.1f}", f"{m['max']:.1f}"
            )
        console.print(metrics)
