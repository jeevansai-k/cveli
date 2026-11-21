"""``cveli privacy`` — privacy notice and data purge."""

from __future__ import annotations

import typer

from cli.commands.common import console
from services.projects import ProjectService

privacy_app = typer.Typer(
    help="Privacy notice and purge of saved research data.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

PRIVACY_NOTICE = """\
CVELI privacy notice
• Usernames, target domains and generated dorks stay in memory and are never
  written to logs or metrics. They are stored only when you explicitly save
  them to a research project (SQLite, on this machine).
• The audit log records event types and identifiers (CVE/EDB IDs, template
  ids, risk levels) — never your inputs. Default retention: 90 days.
• Local metrics record timings/counters only. Nothing is sent anywhere.
• External requests go only to NVD, CVE.org, CISA, FIRST and GitLab
  (Exploit-DB CSV). Google is opened in *your* browser only when you ask.
• Remove everything saved with: cveli privacy purge
"""


@privacy_app.command("notice")
def notice():
    """Show the privacy notice and data-retention policy."""
    console.print(PRIVACY_NOTICE, markup=False)


@privacy_app.command("purge")
def purge(
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation"),
):
    """Delete projects, saved dorks/searches, report records and the audit log."""
    if not yes and not typer.confirm("Permanently delete all saved research data?"):
        raise typer.Exit(code=1)
    removed = ProjectService().purge_all()
    console.print(f"[success]✓ Purged {removed} record(s)[/success]")
