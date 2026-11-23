"""
Opus 5.5 component library (Textual widgets).

Every component uses theme tokens via TCSS classes (``cli/tui/cveli.tcss``);
none contain colour literals. Meaning is never conveyed by colour alone:
severity badges carry a symbol + word, safety labels carry their text.
"""

from __future__ import annotations

from collections.abc import Callable

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widget import Widget
from textual.widgets import Button, Checkbox, HelpPanel, Static, TextArea

from cli.tui.theme import SEVERITY_SYMBOLS
from core.models import SafetyLabel
from core.text import sanitize_terminal_text


def severity_class(severity: str | None) -> str:
    sev = (severity or "none").lower()
    return f"sev-{sev}" if sev in {"critical", "high", "medium", "low"} else "sev-none"


class SeverityBadge(Static):
    """``◆ CRITICAL`` — symbol + word + token colour."""

    def __init__(self, severity: str | None, **kwargs) -> None:
        sev = (severity or "N/A").upper()
        super().__init__(
            f"{SEVERITY_SYMBOLS.get(sev, '–')} {sev}",
            classes=f"badge {severity_class(severity)}",
            **kwargs,
        )


SAFETY_CLASSES = {
    SafetyLabel.RESEARCH_ONLY.value: "label-research",
    SafetyLabel.REQUIRES_AUTHORIZED_ENV.value: "label-research",
    SafetyLabel.POC_REFERENCE.value: "label-poc",
    SafetyLabel.UNVERIFIED.value: "label-unverified",
    SafetyLabel.PATCH_REFERENCE.value: "label-patch",
}


class SafetyBadge(Static):
    def __init__(self, label: str, **kwargs) -> None:
        super().__init__(
            f"[{label}]",
            classes=f"badge {SAFETY_CLASSES.get(label, 'muted')}",
            markup=False,
            **kwargs,
        )


class RiskBadge(Static):
    def __init__(self, risk: str, **kwargs) -> None:
        symbol = {"low": "●", "medium": "▲", "high": "◆"}.get(risk, "·")
        super().__init__(
            f"{symbol} {risk.upper()} RISK",
            classes=f"badge risk-{risk}",
            **kwargs,
        )


class EmptyState(Vertical):
    def __init__(self, title: str, hint: str = "", **kwargs) -> None:
        super().__init__(**kwargs)
        self._title = title
        self._hint = hint

    def compose(self) -> ComposeResult:
        yield Static(self._title, classes="state-title", markup=False)
        if self._hint:
            yield Static(self._hint, classes="muted", markup=False)


class ErrorState(Vertical):
    """Cause + next step, readable without colour."""

    def __init__(self, title: str, cause: str, next_step: str = "", **kwargs) -> None:
        super().__init__(**kwargs)
        self._title = title
        self._cause = cause
        self._next = next_step

    def compose(self) -> ComposeResult:
        yield Static(f"✗ {self._title}", classes="state-title", markup=False)
        yield Static(sanitize_terminal_text(self._cause), markup=False)
        if self._next:
            yield Static(f"Next step: {self._next}", classes="muted", markup=False)


class Notice(Static):
    def __init__(self, text: str, info: bool = False, **kwargs) -> None:
        classes = "notice notice-info" if info else "notice"
        super().__init__(text, classes=classes, markup=False, **kwargs)


class CodeBlock(Vertical):
    """Read-only, syntax-highlighted code with a copy button."""

    def __init__(
        self,
        code: str,
        language: str | None = None,
        title: str = "",
        copy_label: str = "Copy",
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.code = code
        self.language = language
        self.title = title
        self.copy_label = copy_label

    def compose(self) -> ComposeResult:
        with Horizontal(classes="codeblock-bar"):
            yield Static(self.title or (self.language or "text"), markup=False)
            yield Button(self.copy_label, id="copy", variant="default")
        area = TextArea(self.code, read_only=True)
        if self.language and self.language in area.available_languages:
            area.language = self.language
        area = TextArea(
            self.code,
            language=area.language,
            read_only=True,
            show_line_numbers=self.language == "ruby",
            soft_wrap=self.language != "ruby",
        )
        area.can_focus = True
        yield area

    def update_code(self, code: str) -> None:
        self.code = code
        self.query_one(TextArea).load_text(code)

    @on(Button.Pressed, "#copy")
    def copy(self, event: Button.Pressed) -> None:
        event.stop()
        self.app.copy_to_clipboard(self.code)
        self.app.notify("Copied to clipboard (OSC 52).", title="Copied", timeout=3)


class ConfirmModal(ModalScreen):
    """Explicit attestation dialog (authorization / research-only).

    Dismisses with ``True`` when confirmed (subclasses may return a richer
    value via :meth:`result`) and ``False`` when cancelled.
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title: str, body: str, checkbox_label: str) -> None:
        super().__init__()
        self._title = title
        self._body = body
        self._checkbox_label = checkbox_label

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(self._title, classes="view-title", markup=False)
            yield Static(self._body, markup=False)
            yield from self.extra_widgets()
            yield Checkbox(self._checkbox_label, id="attest")
            yield Static("", id="dialog_hint", classes="muted", markup=False)
            with Horizontal(id="dialog_buttons"):
                yield Button("Confirm", id="confirm", variant="warning", disabled=True)
                yield Button("Cancel", id="cancel")

    def extra_widgets(self) -> ComposeResult:
        """Hook for subclasses to add controls above the attestation."""
        yield from ()

    def on_mount(self) -> None:
        self.query_one("#attest", Checkbox).focus()

    def ready(self) -> bool:
        return self.query_one("#attest", Checkbox).value

    def result(self):
        return True

    def _refresh_confirm(self) -> None:
        self.query_one("#confirm", Button).disabled = not self.ready()

    @on(Checkbox.Changed)
    def _toggle(self, event: Checkbox.Changed) -> None:
        self._refresh_confirm()

    @on(Button.Pressed, "#confirm")
    def _confirm(self) -> None:
        if self.ready():
            self.dismiss(self.result())

    @on(Button.Pressed, "#cancel")
    def _cancel_button(self) -> None:
        self.dismiss(False)

    def action_cancel(self) -> None:
        self.dismiss(False)


EXPORT_FORMAT_CHOICES = (
    ("rb", "Ruby scaffold (.rb)"),
    ("md", "Research report (.md)"),
    ("json", "Metadata (.json)"),
)


class ExportConfirmModal(ConfirmModal):
    """Research-only confirmation that also lets the user pick file types.

    Dismisses with the list of chosen formats (e.g. ``["json", "md"]``) or
    ``False`` when cancelled.
    """

    def __init__(
        self,
        title: str,
        body: str,
        checkbox_label: str,
        selected: tuple[str, ...] = ("rb", "md", "json"),
    ) -> None:
        super().__init__(title, body, checkbox_label)
        self._selected = selected

    def extra_widgets(self) -> ComposeResult:
        yield Static("File types to export:", classes="label", markup=False)
        with Horizontal(id="export_formats"):
            for fmt, label in EXPORT_FORMAT_CHOICES:
                yield Checkbox(label, value=fmt in self._selected, id=f"fmt_{fmt}")

    def selected_formats(self) -> list[str]:
        return [
            fmt
            for fmt, _label in EXPORT_FORMAT_CHOICES
            if self.query_one(f"#fmt_{fmt}", Checkbox).value
        ]

    def ready(self) -> bool:
        formats = self.selected_formats()
        hint = "" if formats else "Select at least one file type."
        self.query_one("#dialog_hint", Static).update(hint)
        return super().ready() and bool(formats)

    def result(self):
        return self.selected_formats()


class ProjectPickerModal(ModalScreen):
    """Choose an existing research project or create a new one.

    Dismisses with the chosen project's id, or ``None`` when cancelled.
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, item_label: str) -> None:
        super().__init__()
        self._item_label = item_label

    def compose(self) -> ComposeResult:
        from textual.widgets import Input, OptionList
        from textual.widgets.option_list import Option

        from services.projects import ProjectService

        projects = ProjectService().list()
        with Vertical(id="dialog"):
            yield Static("Add to project", classes="view-title", markup=False)
            yield Static(f"Item: {self._item_label}", markup=False)
            if projects:
                yield Static(
                    "Choose an existing project (Enter to add):",
                    classes="label",
                    markup=False,
                )
                yield OptionList(
                    *[
                        Option(
                            f"{p['name']}  ·  {p['item_count']} item(s), "
                            f"{p['dork_count']} dork(s)",
                            id=p["id"],
                        )
                        for p in projects
                    ],
                    id="project_choices",
                )
            else:
                yield Static("No projects yet — create one below.", classes="muted")
            yield Static("…or create a new project:", classes="label", markup=False)
            with Horizontal(id="new_project_row"):
                yield Input(placeholder="New project name", id="new_project_name")
                yield Button("Create & add", id="create_project", variant="primary")
            with Horizontal(id="dialog_buttons"):
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        from textual.widgets import Input, OptionList

        choices = self.query("#project_choices")
        if choices:
            choices.first(OptionList).focus()
        else:
            self.query_one("#new_project_name", Input).focus()

    def on_option_list_option_selected(self, event) -> None:
        if event.option.id:
            self.dismiss(event.option.id)

    @on(Button.Pressed, "#create_project")
    def _create(self) -> None:
        from textual.widgets import Input

        from services.projects import ProjectService
        from utils.errors import AppError

        name = self.query_one("#new_project_name", Input).value.strip()
        if not name:
            self.app.notify("Enter a project name.", severity="warning")
            return
        try:
            project = ProjectService().create(name)
        except AppError as error:
            self.app.notify(str(error), title="Projects", severity="error")
            return
        self.dismiss(project["id"])

    def on_input_submitted(self, event) -> None:
        if event.input.id == "new_project_name":
            self._create()

    @on(Button.Pressed, "#cancel")
    def _cancel_button(self) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


def add_to_project(app, kind: str, item_id: str, label: str) -> None:
    """Open the project picker and add ``item_id`` to the chosen project."""

    def done(project_id: str | None) -> None:
        if not project_id:
            return
        from services.projects import ProjectService
        from utils.errors import AppError

        service = ProjectService()
        try:
            service.add(project_id, kind, item_id)
            name = service.projects.require(project_id)["name"]
        except AppError as error:
            app.notify(str(error), title="Projects", severity="error")
            return
        app.notify(f"{label} added to project '{name}'.", timeout=4)

    app.push_screen(ProjectPickerModal(label), done)


class KeyValue(Static):
    def __init__(self, key: str, value: str | None, **kwargs) -> None:
        text = Text()
        text.append(f"{key}: ", style="bold")
        text.append(sanitize_terminal_text(value) if value else "N/A")
        super().__init__(text, **kwargs)


def call_safely(widget: Widget, func: Callable[[], None], title: str) -> bool:
    """Run ``func``; show a toast instead of crashing on any application error."""
    from utils.errors import AppError

    try:
        func()
        return True
    except AppError as error:
        widget.app.notify(str(error), title=title, severity="error", timeout=6)
    except Exception as error:  # pragma: no cover - defensive
        widget.app.notify(
            f"Unexpected error: {error}", title=title, severity="error", timeout=6
        )
    return False


KEYS_CLOSE_HINT = "To close this page select [keys] from palette again"


class CveliHelpPanel(HelpPanel):
    """The palette's "Keys" guide, with a hint on how to close it again.

    It inherits from Textual's ``HelpPanel`` so the palette still recognises it
    (and offers "Keys" again to hide it).
    """

    DEFAULT_CSS = """
    CveliHelpPanel #keys-close-hint {
        height: auto;
        padding: 0 1 1 1;
        color: $warning;
        text-style: bold;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(KEYS_CLOSE_HINT, id="keys-close-hint", markup=False)
        yield from super().compose()


class CveliHelpMixin:
    """Mount :class:`CveliHelpPanel` instead of the stock help panel."""

    def action_show_help_panel(self) -> None:
        screen = self.screen  # type: ignore[attr-defined]
        if not screen.query("HelpPanel"):
            screen.mount(CveliHelpPanel())
