"""``cveli jobs`` — run maintenance/background jobs (cron friendly)."""

from __future__ import annotations

import typer

from cli.commands.common import console, emit_json
from services.jobs import JOBS, run_due_jobs, run_job

jobs_app = typer.Typer(
    help="Run background jobs: exploitdb_refresh, cve_enrichment, cache_cleanup, "
    "index_rebuild.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)


@jobs_app.command("list")
def list_jobs():
    """List available jobs."""
    for name, func in JOBS.items():
        console.print(f"[title]{name}[/title]  {(func.__doc__ or '').strip()}")


@jobs_app.command("run")
def run(
    name: str = typer.Argument(..., help="Job name, or 'due' for stale-only jobs"),
    force: bool = typer.Option(False, "--force", help="Ignore freshness TTLs"),
    as_json: bool = typer.Option(False, "--json", help="Output JSON"),
):
    """Run one job now (use 'due' to run only stale jobs)."""
    if name != "due" and name not in JOBS:
        raise typer.BadParameter(f"Unknown job. Choose: due, {', '.join(JOBS)}")
    with console.status(f"[info]Running {name}…[/info]"):
        result = run_due_jobs() if name == "due" else run_job(name, force=force)
    if as_json:
        emit_json(result)
    else:
        console.print(f"[success]✓ {name}[/success] {result}", markup=False)
