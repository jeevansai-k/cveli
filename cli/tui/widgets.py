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
from textual.widgets import Button, Checkbox, Static, TextArea

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
        area = TextArea(
            self.code,
            language=self.language,
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


class ConfirmModal(ModalScreen[bool]):
    """Explicit attestation dialog (authorization / research-only)."""

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
            yield Checkbox(self._checkbox_label, id="attest")
            with Horizontal(id="dialog_buttons"):
                yield Button("Confirm", id="confirm", variant="warning", disabled=True)
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one(Checkbox).focus()

    @on(Checkbox.Changed, "#attest")
    def _toggle(self, event: Checkbox.Changed) -> None:
        self.query_one("#confirm", Button).disabled = not event.value

    @on(Button.Pressed, "#confirm")
    def _confirm(self) -> None:
        if self.query_one(Checkbox).value:
            self.dismiss(True)

    @on(Button.Pressed, "#cancel")
    def _cancel_button(self) -> None:
        self.dismiss(False)

    def action_cancel(self) -> None:
        self.dismiss(False)


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
