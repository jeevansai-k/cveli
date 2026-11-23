"""Metasploit research-template view + review screen (preview → confirm → export)."""

from __future__ import annotations

from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    Footer,
    Input,
    LoadingIndicator,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from cli.tui.views.base import View
from cli.tui.widgets import CodeBlock, EmptyState, ExportConfirmModal, Notice
from core.models import TemplateBundle
from core.msf import PREFLIGHT_CHECKLIST
from core.msf.render import to_json_text
from core.safety import RESEARCH_CONFIRMATION_PROMPT
from services.msf_template import MsfTemplateService
from utils.errors import AppError

MODULE_TYPES = [
    ("Auto (from Exploit-DB type)", "auto"),
    ("exploit", "exploit"),
    ("auxiliary", "auxiliary"),
    ("post", "post"),
]
SCAFFOLD_NOTICE = (
    "Research template only: no payload, no exploitation logic, no network I/O. "
    "check() returns Unknown and the action method always stops with fail_with."
)


class TemplatePreview(Vertical):
    """Tabbed preview of a bundle with export controls."""

    def __init__(self, bundle: TemplateBundle, **kwargs) -> None:
        super().__init__(**kwargs)
        self.bundle = bundle

    def compose(self) -> ComposeResult:
        b = self.bundle
        yield Static(
            f"{b.id} · {b.module_type} ({b.module_class}) · "
            f"{b.cve_id or ''} {('EDB-' + str(b.edb_id)) if b.edb_id else ''}",
            classes="section-title",
            markup=False,
        )
        yield Notice(SCAFFOLD_NOTICE)
        yield Static(
            "Preflight checklist:\n"
            + "\n".join(f"  [ ] {i}" for i in PREFLIGHT_CHECKLIST),
            markup=False,
        )
        with TabbedContent(id="tpl_tabs"):
            with TabPane("Ruby scaffold", id="tab_rb"):
                yield CodeBlock(b.ruby, language="ruby", title=f"{b.id}.rb")
            with TabPane("Research report", id="tab_md"):
                yield CodeBlock(b.markdown, language="markdown", title=f"{b.id}.md")
            with TabPane("Metadata", id="tab_json"):
                yield CodeBlock(
                    to_json_text(b.metadata), language="json", title=f"{b.id}.json"
                )
        with Horizontal(classes="form-row"):
            yield Input(value="cveli-templates", id="tpl_out", classes="field")
            yield Button("Export .rb/.md/.json…", id="tpl_export", variant="warning")

    @on(Button.Pressed, "#tpl_export")
    def request_export(self) -> None:
        out_dir = self.query_one("#tpl_out", Input).value.strip() or "cveli-templates"

        def done(formats: list[str] | bool | None) -> None:
            if not formats or formats is True:
                self.app.notify("Export cancelled.", timeout=2)
                return
            try:
                written = MsfTemplateService().export(
                    self.bundle, out_dir, formats=formats, confirmed=True
                )
            except AppError as error:
                self.app.notify(str(error), title="Export failed", severity="error")
                return
            self.app.notify(
                "Exported:\n" + "\n".join(written), title="Template exported", timeout=8
            )

        self.app.push_screen(
            ExportConfirmModal(
                "Research-only confirmation",
                "Before exporting, confirm every preflight item:\n"
                + "\n".join(f"  • {item}" for item in PREFLIGHT_CHECKLIST),
                RESEARCH_CONFIRMATION_PROMPT,
            ),
            done,
        )


def generate_bundle(cve_id: str | None, edb_id: int | None, module_type: str):
    return MsfTemplateService().generate(
        cve_id=cve_id, edb_id=edb_id, module_type=module_type, live=True
    )


class TemplateScreen(Screen):
    """Review screen opened from CVE/Exploit detail screens (key M)."""

    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def __init__(self, cve_id: str | None = None, edb_id: int | None = None) -> None:
        super().__init__()
        self.cve_id = cve_id
        self.edb_id = edb_id

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="tpl_screen_body", classes="detail_shell"):
            yield LoadingIndicator()
        yield Footer()

    def on_mount(self) -> None:
        self._generate()

    @work(thread=True, exclusive=True, group="tpl-screen")
    def _generate(self) -> None:
        try:
            bundle = generate_bundle(self.cve_id, self.edb_id, "auto")
        except AppError as error:
            self.app.call_from_thread(self._show, None, str(error))
            return
        self.app.call_from_thread(self._show, bundle, "")

    def _show(self, bundle: TemplateBundle | None, error: str) -> None:
        body = self.query_one("#tpl_screen_body")
        body.remove_children()
        if bundle is None:
            body.mount(EmptyState("Cannot generate a template", error))
        else:
            body.mount(TemplatePreview(bundle))


class TemplatesView(View):
    view_id = "templates"
    label = "MSF Templates"
    icon = "⎔"
    feature = "feature_msf"

    def compose(self) -> ComposeResult:
        yield Static("Metasploit research templates", classes="view-title")
        yield Static(
            "Generate a structured, non-weaponized module scaffold plus a research "
            "report for a CVE and/or Exploit-DB entry. Review it, then export.",
            classes="view-subtitle",
        )
        with Horizontal(classes="form-row"):
            yield Input(placeholder="CVE-ID", id="tpl_cve", classes="field")
            yield Input(placeholder="EDB-ID", id="tpl_edb", classes="field")
            yield Select(MODULE_TYPES, value="auto", allow_blank=False, id="tpl_type")
            yield Button("Generate preview", id="tpl_generate", variant="primary")
        yield Vertical(id="tpl_result")

    def focus_primary(self) -> None:
        self.query_one("#tpl_cve", Input).focus()

    @on(Button.Pressed, "#tpl_generate")
    @on(Input.Submitted, "#tpl_cve")
    @on(Input.Submitted, "#tpl_edb")
    def generate(self) -> None:
        cve = self.query_one("#tpl_cve", Input).value.strip() or None
        edb_raw = (
            self.query_one("#tpl_edb", Input).value.strip().upper().removeprefix("EDB-")
        )
        result = self.query_one("#tpl_result", Vertical)
        result.remove_children()
        if edb_raw and not edb_raw.isdigit():
            result.mount(EmptyState("Invalid EDB-ID", "Use digits, e.g. 50592."))
            return
        result.mount(LoadingIndicator())
        self._generate(
            cve,
            int(edb_raw) if edb_raw else None,
            str(self.query_one("#tpl_type", Select).value),
        )

    @work(thread=True, exclusive=True, group="tpl-view")
    def _generate(self, cve: str | None, edb: int | None, module_type: str) -> None:
        try:
            bundle = generate_bundle(cve, edb, module_type)
        except AppError as error:
            self.app.call_from_thread(self._show, None, str(error))
            return
        self.app.call_from_thread(self._show, bundle, "")

    def _show(self, bundle: TemplateBundle | None, error: str) -> None:
        result = self.query_one("#tpl_result", Vertical)
        result.remove_children()
        if bundle is None:
            result.mount(EmptyState("Cannot generate a template", error))
        else:
            result.mount(TemplatePreview(bundle))
