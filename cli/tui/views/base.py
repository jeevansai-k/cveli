"""Base class for shell workspace views."""

from __future__ import annotations

from textual.containers import VerticalScroll


class View(VerticalScroll):
    """A workspace view. Subclasses set ``view_id``, ``label`` and ``icon``."""

    view_id = "view"
    label = "View"
    icon = "·"
    feature: str | None = None  # settings flag name, e.g. "feature_exploitdb"

    def on_show_view(self) -> None:
        """Hook called whenever the view becomes visible."""

    def focus_primary(self) -> None:
        """Move focus to the view's main input (keyboard-first navigation)."""
        for widget in self.query("Input, DataTable, Button"):
            if widget.focusable:
                widget.focus()
                return
