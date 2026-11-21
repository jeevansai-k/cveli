"""Dork Builder view: inputs → previewed, explained, copyable queries."""

from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Checkbox, Input, Select, Static

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
            yield Input(
                placeholder="filetype (pdf, docx…)", id="dork_filetype", classes="field"
            )
        with Horizontal(classes="form-row"):
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
        preview.remove_children()
        try:
            self.dorks = self.builder.build(self.collect())
        except AppError as error:
            self.dorks = []
            preview.mount(EmptyState("Cannot build this query", str(error)))
            self.app.notify(str(error), title="Dork Builder", severity="error")
            return
        for index, dork in enumerate(self.dorks):
            card = Vertical(classes="card", id=f"dork_card_{index}")
            preview.mount(card)
            card.mount(
                Horizontal(
                    Static(
                        f"{dork.label} · {dork.id}",
                        classes="section-title",
                        markup=False,
                    ),
                    RiskBadge(dork.risk_level),
                    classes="card-row",
                )
            )
            card.mount(CodeBlock(dork.query, title="query", copy_label="Copy"))
            card.mount(Static(dork.explanation, classes="muted", markup=False))
            card.mount(
                Static(
                    "\n".join(
                        f"  {op.op:<10} {op.explanation}" for op in dork.operators
                    ),
                    markup=False,
                )
            )
            for warning in dork.warnings[1:]:
                card.mount(Notice(warning))
            card.mount(
                Horizontal(
                    Button(
                        "Open in browser", id=f"dork_open_{index}", variant="warning"
                    ),
                    Button("Save to project", id=f"dork_save_{index}"),
                    classes="form-row",
                )
            )

    def _index(self, button_id: str, prefix: str) -> DorkQuery | None:
        try:
            return self.dorks[int(button_id.removeprefix(prefix))]
        except (ValueError, IndexError):
            return None

    @on(Button.Pressed)
    def _card_buttons(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id.startswith("dork_open_"):
            dork = self._index(button_id, "dork_open_")
            if dork:
                self.request_open(dork)
        elif button_id.startswith("dork_save_"):
            dork = self._index(button_id, "dork_save_")
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
            self.builder.open(dork, attested=True)
            self.app.notify("Opened in your browser.", timeout=3)
        except RateLimitError as error:
            self.app.notify(str(error), title="Rate limited", severity="warning")
        except AppError as error:
            self.app.notify(str(error), title="Blocked", severity="error")

    def save(self, dork: DorkQuery) -> None:
        from services.projects import ProjectService

        try:
            ProjectService().save_dork("Default research", dork.model_dump())
            self.app.notify("Saved to project 'Default research'.", timeout=3)
        except AppError as error:
            self.app.notify(str(error), severity="error")
