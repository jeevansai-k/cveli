"""
CVELI shell — the Opus 5.5 Textual application.

Layout: top command bar (global search + source status) · left navigation ·
centre workspace (``ContentSwitcher`` of views) · right intelligence panel ·
footer key hints. Responsive via ``HORIZONTAL_BREAKPOINTS``; keyboard-first.
"""

from __future__ import annotations

import re

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import ContentSwitcher, Footer, Input, OptionList, Static
from textual.widgets.option_list import Option

from cli.tui.theme import DARK, apply_theme, resolve_theme_name
from cli.tui.views.base import View
from config.settings import get_settings
from config.version import __version__
from core.formatter import format_cvss, format_epss, severity_label
from core.models import CVEModel
from core.text import one_line

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
EDB_RE = re.compile(r"^(?:EDB-?)?(\d{1,7})$", re.IGNORECASE)


def build_views() -> list[View]:
    from cli.tui.views.dashboard import DashboardView
    from cli.tui.views.search import SearchView
    from cli.tui.views.settings import SettingsView
    from cli.tui.views.watchlist import WatchlistView

    views: list[View] = [DashboardView(id="dashboard"), SearchView(id="search")]
    settings = get_settings()
    optional = []
    try:
        from cli.tui.views.exploits import ExploitsView

        optional.append(("feature_exploitdb", ExploitsView))
    except ImportError:  # pragma: no cover - during phased development
        pass
    try:
        from cli.tui.views.dorks import DorksView

        optional.append(("feature_dorks", DorksView))
    except ImportError:  # pragma: no cover
        pass
    try:
        from cli.tui.views.templates import TemplatesView

        optional.append(("feature_msf", TemplatesView))
    except ImportError:  # pragma: no cover
        pass
    for flag, cls in optional:
        if getattr(settings, flag, True):
            views.append(cls(id=cls.view_id))
    views.append(WatchlistView(id="watchlist"))
    try:
        from cli.tui.views.projects import ProjectsView

        views.append(ProjectsView(id="projects"))
    except ImportError:  # pragma: no cover
        pass
    views.append(SettingsView(id="settings"))
    return views


class IntelPanel(VerticalScroll):
    """Right-hand intelligence panel for the highlighted CVE."""

    def compose(self) -> ComposeResult:
        yield Static("Intel", classes="section-title")
        yield Static(
            "Highlight a CVE to see risk signals.", id="intel_body", markup=False
        )

    def show_cve(self, cve: CVEModel) -> None:
        exploits = 0
        try:
            from storage.exploit_repository import ExploitRepository

            exploits = len(ExploitRepository().for_cve(cve.id))
        except Exception:
            exploits = cve.public_exploit_count
        lines = [
            cve.id,
            "",
            f"Severity   {severity_label(cve.severity)}",
            f"CVSS       {format_cvss(cve.cvss)}",
            f"EPSS       {format_epss(cve.epss)}",
            f"Percentile {format_epss(cve.epss_percentile)}",
            f"CISA KEV   {'YES ' + cve.kev_date if cve.kev else 'no'}",
            f"Exploit-DB {exploits} reference(s)",
            f"Vendor     {one_line(cve.vendor or 'N/A', 22)}",
            f"Published  {cve.published or 'N/A'}",
            "",
            one_line(cve.summary, 400) or "N/A",
            "",
            "Enter: details · M: research template",
        ]
        self.query_one("#intel_body", Static).update("\n".join(lines))


class CveliApp(App):
    CSS_PATH = "cveli.tcss"
    TITLE = "CVELI"
    SUB_TITLE = f"v{__version__}"
    HORIZONTAL_BREAKPOINTS = [(0, "-narrow"), (80, "-medium"), (120, "-wide")]
    is_shell = True

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", priority=True),
        Binding("ctrl+t", "toggle_theme", "Theme"),
        Binding("ctrl+b", "toggle_nav", "Nav"),
        Binding("f2", "toggle_intel", "Intel"),
        Binding("ctrl+f", "focus_search", "Search", show=False),
        Binding("slash", "focus_search", "Search", show=False),
        Binding("q", "quit", "Quit", show=False),
        *[
            Binding(str(index), f"show_view_index({index - 1})", show=False)
            for index in range(1, 10)
        ],
    ]

    def __init__(self) -> None:
        super().__init__()
        from cli.tui.commands import CveliCommands

        self.COMMANDS = App.COMMANDS | {CveliCommands}
        apply_theme(self)
        self.views = build_views()
        self.research_attested = False  # session-scoped authorization attestation

    # --- layout -----------------------------------------------------------
    def compose(self) -> ComposeResult:
        with Horizontal(id="command_bar"):
            yield Static("CVELI", id="app_title")
            yield Input(
                placeholder="Search CVE-ID, EDB-ID or keyword  ( / )",
                id="global_search",
            )
            yield Static("", id="source_status", markup=False)
        with Horizontal(id="body"):
            yield OptionList(
                *[
                    Option(f"{index}  {view.icon} {view.label}", id=view.view_id)
                    for index, view in enumerate(self.views, start=1)
                ],
                id="nav",
            )
            with ContentSwitcher(initial="dashboard", id="workspace"):
                yield from self.views
            yield IntelPanel(id="intel")
        yield Footer()

    def on_mount(self) -> None:
        from storage.system_repositories import SettingsRepository

        try:
            reduce_motion = get_settings().reduce_motion or bool(
                SettingsRepository().get("reduce_motion")
            )
        except Exception:
            reduce_motion = get_settings().reduce_motion
        if reduce_motion:
            self.animation_level = "none"
        self.update_source_status()
        nav = self.query_one("#nav", OptionList)
        nav.highlighted = 0
        nav.focus()

    # --- responsive navigation --------------------------------------------
    def on_resize(self, event) -> None:
        self._compact_nav(event.size.width < 80)

    def _compact_nav(self, compact: bool) -> None:
        if getattr(self, "_nav_compact", None) == compact:
            return
        self._nav_compact = compact
        nav = self.query_one("#nav", OptionList)
        for index, view in enumerate(self.views, start=1):
            prompt = (
                f"{index} {view.icon}"
                if compact
                else f"{index}  {view.icon} {view.label}"
            )
            nav.replace_option_prompt(view.view_id, prompt)

    # --- navigation -------------------------------------------------------
    def view_ids(self) -> list[str]:
        return [view.view_id for view in self.views]

    def show_view(self, view_id: str, focus: bool = True) -> View | None:
        if view_id not in self.view_ids():
            self.notify(f"'{view_id}' is disabled or unavailable.", severity="warning")
            return None
        switcher = self.query_one("#workspace", ContentSwitcher)
        switcher.current = view_id
        view = self.query_one(f"#{view_id}", View)
        nav = self.query_one("#nav", OptionList)
        nav.highlighted = self.view_ids().index(view_id)
        view.on_show_view()
        if focus:
            view.focus_primary()
        return view

    def action_show_view_index(self, index: int) -> None:
        ids = self.view_ids()
        if 0 <= index < len(ids):
            self.show_view(ids[index])

    @on(OptionList.OptionSelected, "#nav")
    def _nav_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option.id:
            self.show_view(event.option.id)

    def action_toggle_nav(self) -> None:
        self.query_one("#nav").toggle_class("-hidden")

    def action_toggle_intel(self) -> None:
        intel = self.query_one("#intel")
        if self.screen.has_class("-medium"):
            intel.toggle_class("-pinned")
        else:
            intel.toggle_class("-hidden")

    def action_focus_search(self) -> None:
        self.query_one("#global_search", Input).focus()

    # --- global search ----------------------------------------------------
    @on(Input.Submitted, "#global_search")
    def _global_search(self, event: Input.Submitted) -> None:
        self.route_query(event.value.strip())

    def route_query(self, value: str) -> None:
        value = value.strip()
        if not value:
            return
        edb = EDB_RE.match(value)
        if edb and value.upper().startswith("EDB") and "exploits" in self.view_ids():
            view = self.show_view("exploits", focus=False)
            if view is not None:
                view.search(edb_id=int(edb.group(1)))  # type: ignore[attr-defined]
            return
        view = self.show_view("search", focus=False)
        if view is not None:
            query = value.upper() if CVE_RE.match(value) else value
            view.run_search(query, live=True)  # type: ignore[attr-defined]

    # --- intel / status ---------------------------------------------------
    def show_intel(self, cve: CVEModel) -> None:
        self.query_one(IntelPanel).show_cve(cve)

    def update_source_status(self) -> None:
        try:
            from storage.system_repositories import SourceStateRepository

            state = SourceStateRepository()
            parts = []
            for source, label in (
                ("exploitdb", "EDB"),
                ("cisa_kev", "KEV"),
                ("nvd", "NVD"),
            ):
                row = state.get(source)
                last = row["last_success"]
                parts.append(f"{label} {last.strftime('%m-%d') if last else '—'}")
            self.query_one("#source_status", Static).update(" · ".join(parts))
        except Exception:
            pass

    # --- theme ------------------------------------------------------------
    def set_theme_preference(self, choice: str) -> None:
        from storage.system_repositories import SettingsRepository

        SettingsRepository().set("theme", choice)
        self.theme = resolve_theme_name(choice)
        self.notify(f"Theme: {self.theme}", timeout=2)

    def action_toggle_theme(self) -> None:
        self.set_theme_preference("light" if self.theme == DARK else "dark")


def run() -> None:
    CveliApp().run()


if __name__ == "__main__":  # pragma: no cover
    run()
