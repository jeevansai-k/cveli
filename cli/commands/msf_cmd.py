"""
``cveli msf`` — Metasploit *research template* generator.

Review first (preview is the default), export only after an explicit
research-only confirmation. Output is a scaffold, never a working exploit.
"""

from __future__ import annotations

import typer
from rich.markup import escape
from rich.syntax import Syntax
from rich.text import Text

from cli.commands.common import check_format, console, emit_json, guard, require_feature
from core.safety import RESEARCH_CONFIRMATION_PROMPT
from services.msf_template import EXPORT_FORMATS, MsfTemplateService

msf_app = typer.Typer(
    help="Generate non-weaponized Metasploit research templates (.rb/.md/.json) "
    "for a CVE or Exploit-DB entry.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _edb(value: str | None) -> int | None:
    if not value:
        return None
    digits = value.upper().removeprefix("EDB-")
    if not digits.isdigit():
        raise typer.BadParameter("EDB-ID must be numeric", param_hint="--edb")
    return int(digits)


@msf_app.command("generate")
def generate(
    cve: str | None = typer.Option(None, "--cve", help="CVE ID"),
    edb: str | None = typer.Option(None, "--edb", help="Exploit-DB ID"),
    module_type: str = typer.Option(
        "auto", "--type", help="auto, exploit, auxiliary or post"
    ),
    author: str = typer.Option("CVELI Research", "--author"),
    out: str | None = typer.Option(
        None, "--out", "-o", help="Directory to export into (omit to preview only)"
    ),
    formats: str = typer.Option(
        "rb,md,json", "--formats", help="Comma list of rb, md, json"
    ),
    confirm_research: bool = typer.Option(
        False,
        "--confirm-research",
        help="Confirm research-only / authorized use (otherwise prompted on export)",
    ),
    project: str | None = typer.Option(
        None, "--project", help="Link report to project"
    ),
    offline: bool = typer.Option(False, "--offline", help="Do not fetch missing CVEs"),
    force: bool = typer.Option(False, "--force", help="Allow output outside safe dirs"),
    preview: str = typer.Option(
        "rb", "--preview", help="What to print when not exporting: rb, md, json"
    ),
    output_format: str = typer.Option("text", "--format", "-f", help="text|json"),
):
    """Preview a research template, or export it with --out (+ confirmation)."""
    require_feature("msf")
    fmt = check_format(output_format, ("text", "json"))
    if not cve and not edb:
        raise typer.BadParameter("Provide --cve and/or --edb")
    service = MsfTemplateService()
    bundle = guard(
        lambda: service.generate(
            cve_id=cve,
            edb_id=_edb(edb),
            module_type=module_type,
            author=author,
            live=not offline,
        )
    )
    if out is None:
        if fmt == "json":
            emit_json(bundle.model_dump())
            return
        chosen = check_format(preview, EXPORT_FORMATS)
        if chosen == "rb":
            console.print(
                Syntax(bundle.ruby, "ruby", line_numbers=True, word_wrap=True)
            )
        elif chosen == "md":
            print(bundle.markdown)
        else:
            emit_json(bundle.metadata)
        console.print(
            "[muted]Preview only. Export with --out DIR (requires research-only "
            "confirmation).[/muted]"
        )
        return
    selected = tuple(part.strip() for part in formats.split(",") if part.strip())
    if not confirm_research:
        console.print(Text("Preflight checklist:", style="title"))
        for item in bundle.preflight:
            console.print(Text(f"  [ ] {item}"))
        confirm_research = typer.confirm(RESEARCH_CONFIRMATION_PROMPT, default=False)
    written = guard(
        lambda: service.export(
            bundle,
            out,
            formats=selected,
            confirmed=confirm_research,
            allow_outside=force,
            project=project,
        ),
        exit_code=4,
    )
    if fmt == "json":
        emit_json(
            {
                "module_type": bundle.module_type,
                "module_class": bundle.module_class,
                "files": written,
                "preflight": bundle.preflight,
            }
        )
        return
    console.print(
        f"[success]✓ Exported {bundle.module_type} research template:[/success]"
    )
    for path in written:
        console.print(f"  • [info]{escape(path)}[/info]")


@msf_app.command("history")
def history(limit: int = typer.Option(20, "--limit", "-l", min=1, max=500)):
    """List previously exported templates (paths and identifiers only)."""
    from storage.research_repositories import ReportRepository

    for row in ReportRepository().list(limit):
        edb = f"EDB-{row['edb_id']}" if row["edb_id"] else ""
        console.print(
            Text(
                f"{row['created_at']}  {row['module_type']:<9} "
                f"{row['cve_id'] or ''} {edb}  {', '.join(row['paths'])}"
            )
        )
