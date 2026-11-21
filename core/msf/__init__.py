"""Metasploit *research template* rendering (scaffolds, never working exploits)."""

from .render import (
    FORBIDDEN_PRIMITIVES,
    PREFLIGHT_CHECKLIST,
    TemplateContext,
    choose_module_type,
    render_json,
    render_markdown,
    render_ruby,
)

__all__ = [
    "FORBIDDEN_PRIMITIVES",
    "PREFLIGHT_CHECKLIST",
    "TemplateContext",
    "choose_module_type",
    "render_json",
    "render_markdown",
    "render_ruby",
]
