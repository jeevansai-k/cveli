"""
``cveli dork`` — Google Dork Builder (preview, explain, copy, manual open).

CVELI never runs the searches: queries are printed for you to copy, or opened
in your own browser on request after an authorization confirmation.
"""

from __future__ import annotations

from typing import Annotated

import typer
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cli.commands.common import check_format, console, emit_json, guard, require_feature
from core.dork_templates import CATEGORIES, SITE_PRESETS
from core.models import DorkInput, DorkQuery
from services.dorks import AUTHORIZATION_WARNING, DorkBuilder

dork_app = typer.Typer(
    help="Build safe, explained Google search queries for a username + site. "
    "No automated searching.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

ATTESTATION = (
    "I have written authorization or a lawful research purpose for this target, "
    "and I will respect the site's terms and applicable privacy law."
)


def _input(
    username: str,
    site: str,
    category: str,
    exact: bool,
    exclude_fp: bool,
    filetype: str | None,
    include: list[str] | None,
    exclude: list[str] | None,
    custom: str,
) -> DorkInput:
    return DorkInput(
        username=username,
        target_domain=site,
        category=category,
        exact_match=exact,
        exclude_false_positives=exclude_fp,
        filetype=filetype,
        include_phrases=include or [],
        exclude_phrases=exclude or [],
        custom_query=custom,
    )


def _render(dorks: list[DorkQuery]) -> None:
    console.print(Text(AUTHORIZATION_WARNING), style="warning")
    for dork in dorks:
        body = Text()
        body.append(dork.query + "\n\n", style="code")
        body.append(dork.explanation + "\n", style="muted")
        for op in dork.operators:
            body.append(f"  {op.op:<10}", style="accent")
            body.append(f"{op.explanation}\n")
        for warning in dork.warnings[1:]:
            body.append(f"\n⚠ {warning}", style="warning")
        risk = {"low": "● LOW", "medium": "▲ MEDIUM", "high": "◆ HIGH"}[dork.risk_level]
        console.print(
            Panel(
                body,
                title=Text(f"{dork.label} · {dork.id}"),
                subtitle=Text(f"{risk} RISK"),
                border_style="warning" if dork.risk_level != "low" else "accent",
            )
        )
    console.print(
        "[muted]Copy a query above, or open one with: cveli dork open --template "
        "<id> … (requires confirmation).[/muted]"
    )


@dork_app.command("sites")
def sites():
    """List preset target sites."""
    require_feature("dorks")
    for label, domain in SITE_PRESETS:
        console.print(Text(f"{domain:<24} {label}"))


@dork_app.command("templates")
def templates(output_format: str = typer.Option("table", "--format", "-f")):
    """List dork templates with category and risk level."""
    require_feature("dorks")
    fmt = check_format(output_format, ("table", "json"))
    data = DorkBuilder.templates()
    if fmt == "json":
        emit_json(data)
        return
    table = Table(title="Dork templates", expand=True)
    for column in ("ID", "Category", "Risk", "Pattern"):
        table.add_column(column)
    for row in data:
        table.add_row(
            row["id"], row["category_label"], row["risk_level"], Text(row["pattern"])
        )
    console.print(table)


@dork_app.command("build")
def build(
    site: str = typer.Option("", "--site", "-s", help="Target site/domain"),
    username: str = typer.Option("", "--username", "-u", help="Username or handle"),
    category: str = typer.Option(
        "profiles", "--category", "-c", help=", ".join(CATEGORIES)
    ),
    exact: bool = typer.Option(True, "--exact/--no-exact", help="Quote the username"),
    exclude_fp: bool = typer.Option(
        False, "--exclude-fp", help="Exclude common false positives"
    ),
    filetype: str | None = typer.Option(None, "--filetype", help="pdf, docx, txt…"),
    include: Annotated[
        list[str] | None, typer.Option("--include", help="Required phrase")
    ] = None,
    exclude: Annotated[
        list[str] | None, typer.Option("--exclude", help="Excluded phrase")
    ] = None,
    custom: str = typer.Option("", "--custom", help="Custom query (category=custom)"),
    output_format: str = typer.Option(
        "table", "--format", "-f", help="table|json|plain"
    ),
):
    """Preview dorks for a username and site, with operator explanations."""
    require_feature("dorks")
    fmt = check_format(output_format, ("table", "json", "plain"))
    data = _input(
        username, site, category, exact, exclude_fp, filetype, include, exclude, custom
    )
    dorks = guard(lambda: DorkBuilder().build(data))
    if fmt == "json":
        emit_json([dork.model_dump() for dork in dorks])
    elif fmt == "plain":
        for dork in dorks:
            print(dork.query)
    else:
        _render(dorks)


@dork_app.command("open")
def open_dork(
    template: str = typer.Option(..., "--template", "-t", help="Template id to open"),
    site: str = typer.Option("", "--site", "-s", help="Target site/domain"),
    username: str = typer.Option("", "--username", "-u"),
    category: str = typer.Option("profiles", "--category", "-c"),
    exact: bool = typer.Option(True, "--exact/--no-exact"),
    custom: str = typer.Option("", "--custom"),
    authorized: bool = typer.Option(
        False,
        "--i-am-authorized",
        help="Confirm written authorization / lawful purpose (otherwise prompted)",
    ),
):
    """Open ONE previewed dork in your browser (confirmation + rate limit)."""
    require_feature("dorks")
    builder = DorkBuilder()
    data = _input(username, site, category, exact, False, None, None, None, custom)
    dorks = guard(lambda: builder.build(data))
    chosen = next((d for d in dorks if d.id == template), None)
    if chosen is None:
        ids = ", ".join(d.id for d in dorks)
        console.print(
            f"[danger]Template {escape(template)} not in category. Use: {ids}[/danger]"
        )
        raise typer.Exit(code=2)
    console.print(Text(f"Query: {chosen.query}"), style="code")
    if not authorized:
        authorized = typer.confirm(ATTESTATION, default=False)
    url = guard(lambda: builder.open(chosen, attested=authorized), exit_code=4)
    console.print(f"[success]✓ Opened in your browser:[/success] {escape(url)}")


@dork_app.command("save")
def save(
    project: str = typer.Option(
        ..., "--project", "-p", help="Project name (created if new)"
    ),
    site: str = typer.Option("", "--site", "-s", help="Target site/domain"),
    username: str = typer.Option("", "--username", "-u"),
    category: str = typer.Option("profiles", "--category", "-c"),
    exact: bool = typer.Option(True, "--exact/--no-exact"),
    custom: str = typer.Option("", "--custom"),
):
    """Explicitly save built dorks (including the username) to a research project."""
    require_feature("dorks")
    from services.projects import ProjectService

    data = _input(username, site, category, exact, False, None, None, None, custom)
    dorks = guard(lambda: DorkBuilder().build(data))
    service = ProjectService()
    for dork in dorks:
        guard(lambda dork=dork: service.save_dork(project, dork.model_dump()))
    console.print(
        f"[success]✓ Saved {len(dorks)} dork(s) to project {escape(project)}[/success]"
    )
