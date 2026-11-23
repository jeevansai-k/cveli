"""Dork Builder view: inputs → previewed, explained, copyable queries."""

from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Checkbox, Input, Link, Select, Static

from cli.tui.views.base import View
from cli.tui.widgets import CodeBlock, ConfirmModal, EmptyState, Notice, RiskBadge
from core.dork_templates import CATEGORIES, SITE_PRESETS
from core.models import DorkInput, DorkQuery
from services.dorks import AUTHORIZATION_WARNING, DorkBuilder
from utils.errors import AppError, RateLimitError

CUSTOM_SITE = "__custom__"
PRIVACY = (
    "Privacy: the username and domain stay in memory, are redacted from logs and "
    "are stored only if you press 'Save to project'."
)
ATTEST_LABEL = (
    "I have written authorization or a lawful research purpose for this target."
)


class DorksView(View):
    view_id = "dorks"
    label = "Dork Builder"
    icon = "⚲"
    feature = "feature_dorks"

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.dorks: list[DorkQuery] = []
        self.builder = DorkBuilder()

    def compose(self) -> ComposeResult:
        yield Static("Google Dork Builder", classes="view-title")
        yield Notice(AUTHORIZATION_WARNING)
        yield Static(PRIVACY, classes="muted")
        with Horizontal(classes="form-row"):
            yield Input(
                placeholder="Username or handle", id="dork_username", classes="field"
            )
            yield Select(
                [
                    *[(f"{label} ({d})", d) for label, d in SITE_PRESETS],
                    ("Custom domain…", CUSTOM_SITE),
                ],
                value=SITE_PRESETS[0][1],
                allow_blank=False,
                id="dork_site",
            )
            yield Input(
                placeholder="custom domain e.g. example.com",
                id="dork_domain",
                classes="field",
            )
        with Horizontal(classes="form-row"):
            yield Select(
                [(label, key) for key, label in CATEGORIES.items()],
                value="profiles",
                allow_blank=False,
                id="dork_category",
            )
            yield Checkbox("Exact match", value=True, id="dork_exact")
            yield Checkbox("Exclude false positives", id="dork_fp")
        with Horizontal(classes="form-row"):
            yield Input(
                placeholder="filetype (pdf…)", id="dork_filetype", classes="field"
            )
            yield Input(
                placeholder="Include phrase", id="dork_include", classes="field"
            )
            yield Input(
                placeholder="Exclude phrase", id="dork_exclude", classes="field"
            )
            yield Input(
                placeholder="Custom query (Custom category)",
                id="dork_custom",
                classes="field",
            )
            yield Button("Preview", id="dork_build", variant="primary")
        yield Vertical(id="dork_preview")

    def focus_primary(self) -> None:
        self.query_one("#dork_username", Input).focus()

    def _domain(self) -> str:
        site = str(self.query_one("#dork_site", Select).value)
        if site == CUSTOM_SITE:
            return self.query_one("#dork_domain", Input).value
        custom = self.query_one("#dork_domain", Input).value.strip()
        return custom or site

    def collect(self) -> DorkInput:
        def val(widget_id: str) -> str:
            return self.query_one(widget_id, Input).value.strip()

        return DorkInput(
            username=val("#dork_username"),
            target_domain=self._domain(),
            category=str(self.query_one("#dork_category", Select).value),
            exact_match=self.query_one("#dork_exact", Checkbox).value,
            exclude_false_positives=self.query_one("#dork_fp", Checkbox).value,
            filetype=val("#dork_filetype") or None,
            include_phrases=[val("#dork_include")] if val("#dork_include") else [],
            exclude_phrases=[val("#dork_exclude")] if val("#dork_exclude") else [],
            custom_query=val("#dork_custom"),
        )

    @on(Button.Pressed, "#dork_build")
    @on(Input.Submitted)
    def build(self, event=None) -> None:
        if isinstance(event, Input.Submitted) and not (event.input.id or "").startswith(
            "dork_"
        ):
            return
        preview = self.query_one("#dork_preview", Vertical)
        # Result cards carry no fixed IDs, so rebuilding while the previous
        # cards are still being removed can never collide (this used to crash
        # the app with DuplicateIds on the second "Preview").
        preview.remove_children()
        try:
            self.dorks = self.builder.build(self.collect())
        except AppError as error:
            self.dorks = []
            preview.mount(EmptyState("Cannot build this query", str(error)))
            self.app.notify(str(error), title="Dork Builder", severity="error")
            return
        if not self.dorks:
            preview.mount(EmptyState("No queries for this input", "Try another site."))
            return
        preview.mount(
            Static(
                f"{len(self.dorks)} quer{'y' if len(self.dorks) == 1 else 'ies'} · "
                "Copy a query, click its link, or press 'Open in browser'.",
                classes="muted",
                markup=False,
            ),
            *[self._card(index, dork) for index, dork in enumerate(self.dorks)],
        )

    def _card(self, index: int, dork: DorkQuery) -> Vertical:
        children = [
            Horizontal(
                Static(
                    f"{index + 1}. {dork.label} · {dork.id}",
                    classes="section-title",
                    markup=False,
                ),
                RiskBadge(dork.risk_level),
                classes="card-row",
            ),
            CodeBlock(dork.query, title="query", copy_label="Copy"),
            Static(dork.explanation, classes="muted", markup=False),
            Static(
                "\n".join(f"  {op.op:<10} {op.explanation}" for op in dork.operators),
                markup=False,
            ),
            *[Notice(warning) for warning in dork.warnings[1:]],
            Horizontal(
                Static("Search link:", classes="label", markup=False),
                Link(dork.google_url, url=dork.google_url),
                classes="reference_row",
            ),
            Horizontal(
                Button("Open in browser", classes="dork-open", variant="warning"),
                Button("Copy link", classes="dork-copy-link"),
                Button("Save to project", classes="dork-save"),
                classes="form-row",
            ),
        ]
        card = Vertical(*children, classes="card dork-card")
        card.dork_index = index  # type: ignore[attr-defined]
        return card

    def _dork_for(self, button: Button) -> DorkQuery | None:
        for node in button.ancestors:
            index = getattr(node, "dork_index", None)
            if index is not None:
                return self.dorks[index] if index < len(self.dorks) else None
        return None

    @on(Button.Pressed, ".dork-open")
    def _open_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        dork = self._dork_for(event.button)
        if dork:
            self.request_open(dork)

    @on(Button.Pressed, ".dork-copy-link")
    def _copy_link_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        dork = self._dork_for(event.button)
        if dork:
            self.app.copy_to_clipboard(dork.google_url)
            self.app.notify("Search link copied to the clipboard.", timeout=3)

    @on(Button.Pressed, ".dork-save")
    def _save_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        dork = self._dork_for(event.button)
        if dork:
            self.save(dork)

    def request_open(self, dork: DorkQuery) -> None:
        if getattr(self.app, "research_attested", False):
            self._open(dork)
            return

        def done(confirmed: bool | None) -> None:
            if confirmed:
                self.app.research_attested = True  # type: ignore[attr-defined]
                from services.audit import audit

                audit("research_attested", object_kind="session", category="dorks")
                self._open(dork)

        self.app.push_screen(
            ConfirmModal(
                "Authorized research only",
                f"{AUTHORIZATION_WARNING}\n\nQuery:\n{dork.query}",
                ATTEST_LABEL,
            ),
            done,
        )

    def _open(self, dork: DorkQuery) -> None:
        try:
            url = self.builder.open(dork, attested=True)
        except RateLimitError as error:
            self.app.notify(str(error), title="Rate limited", severity="warning")
        except AppError as error:
            self.app.notify(str(error), title="Blocked", severity="error")
            return
        if self.builder.last_launched:
            self.app.notify("Opened in your browser.", timeout=3)
            return
        # No browser could be launched from this terminal (SSH, WSL, VM, …).
        self.app.copy_to_clipboard(url)
        self.app.notify(
            "No browser could be started from this terminal. The search link was "
            "copied to your clipboard — paste it into your browser:\n" + url,
            title="Open manually",
            severity="warning",
            timeout=12,
        )

    def save(self, dork: DorkQuery) -> None:
        from cli.tui.widgets import ProjectPickerModal

        def done(project_id: str | None) -> None:
            if not project_id:
                return
            from services.projects import ProjectService

            service = ProjectService()
            try:
                service.save_dork(project_id, dork.model_dump())
                name = service.projects.require(project_id)["name"]
            except AppError as error:
                self.app.notify(str(error), severity="error")
                return
            self.app.notify(f"Dork saved to project '{name}'.", timeout=3)

        self.app.push_screen(ProjectPickerModal(f"Dork: {dork.query}"), done)
