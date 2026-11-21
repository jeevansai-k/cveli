"""
Opus 5.5 design tokens.

This is the ONLY module allowed to contain colour literals. Everything else
uses Textual ``$variables`` (TCSS) or Rich style names (``sev.critical``…)
generated from these tokens.

Design direction: premium security console — calm surfaces, high-contrast
text, one restrained accent, semantic colours reserved for meaning.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from rich.theme import Theme as RichTheme
from textual.theme import Theme

DARK = "opus-dark"
LIGHT = "opus-light"
THEME_CHOICES = ("dark", "light", "auto")


@dataclass(frozen=True)
class Palette:
    name: str
    dark: bool
    background: str
    surface: str
    elevated: str
    border: str
    text: str
    muted: str
    primary: str
    secondary: str
    success: str
    warning: str
    danger: str
    info: str
    focus: str
    sev_critical: str
    sev_high: str
    sev_medium: str
    sev_low: str
    sev_none: str

    def text_tokens(self) -> dict[str, str]:
        """Foreground tokens that must meet WCAG AA (4.5:1) on every surface."""
        return {
            "text": self.text,
            "muted": self.muted,
            "primary": self.primary,
            "secondary": self.secondary,
            "success": self.success,
            "warning": self.warning,
            "danger": self.danger,
            "info": self.info,
            "sev-critical": self.sev_critical,
            "sev-high": self.sev_high,
            "sev-medium": self.sev_medium,
            "sev-low": self.sev_low,
            "sev-none": self.sev_none,
        }

    def surface_tokens(self) -> dict[str, str]:
        return {
            "background": self.background,
            "surface": self.surface,
            "elevated": self.elevated,
        }


OPUS_DARK = Palette(
    name=DARK,
    dark=True,
    background="#0D1117",
    surface="#141A22",
    elevated="#1B232E",
    border="#3A4757",
    text="#E6EDF3",
    muted="#A3B1BF",
    primary="#8FD1A8",
    secondary="#9DB8FF",
    success="#6FDC95",
    warning="#F0BE5B",
    danger="#FF8A80",
    info="#79C0FF",
    focus="#FFD479",
    sev_critical="#FF7EB3",
    sev_high="#FF8A80",
    sev_medium="#F0BE5B",
    sev_low="#6FDC95",
    sev_none="#A3B1BF",
)

OPUS_LIGHT = Palette(
    name=LIGHT,
    dark=False,
    background="#F7F8FA",
    surface="#FFFFFF",
    elevated="#EDF0F4",
    border="#8B97A5",
    text="#151B23",
    muted="#4A5563",
    primary="#1F6B45",
    secondary="#2F4FB3",
    success="#1B6E39",
    warning="#7A5000",
    danger="#B3261E",
    info="#0B5BAA",
    focus="#0B5BAA",
    sev_critical="#9C1458",
    sev_high="#B3261E",
    sev_medium="#7A5000",
    sev_low="#1B6E39",
    sev_none="#4A5563",
)

PALETTES = {DARK: OPUS_DARK, LIGHT: OPUS_LIGHT}


def to_textual_theme(palette: Palette) -> Theme:
    return Theme(
        name=palette.name,
        primary=palette.primary,
        secondary=palette.secondary,
        accent=palette.info,
        warning=palette.warning,
        error=palette.danger,
        success=palette.success,
        foreground=palette.text,
        background=palette.background,
        surface=palette.surface,
        panel=palette.elevated,
        dark=palette.dark,
        variables={
            "text-muted": palette.muted,
            "border": palette.border,
            "border-blurred": palette.border,
            "info": palette.info,
            "focus-ring": palette.focus,
            "sev-critical": palette.sev_critical,
            "sev-high": palette.sev_high,
            "sev-medium": palette.sev_medium,
            "sev-low": palette.sev_low,
            "sev-none": palette.sev_none,
            "block-cursor-background": palette.primary,
            "block-cursor-foreground": palette.background,
            "block-cursor-text-style": "bold",
            "footer-key-foreground": palette.primary,
            "input-selection-background": f"{palette.info} 35%",
        },
    )


def to_rich_theme(palette: Palette) -> RichTheme:
    """Rich styles for CLI output, generated from the same tokens."""
    return RichTheme(
        {
            "brand": f"bold {palette.primary}",
            "title": f"bold {palette.text}",
            "muted": palette.muted,
            "accent": palette.primary,
            "link": f"underline {palette.info}",
            "info": palette.info,
            "success": f"bold {palette.success}",
            "warning": f"bold {palette.warning}",
            "danger": f"bold {palette.danger}",
            "cve.id": f"bold {palette.info}",
            "code": palette.text,
            "sev.critical": f"bold {palette.sev_critical}",
            "sev.high": f"bold {palette.sev_high}",
            "sev.medium": f"bold {palette.sev_medium}",
            "sev.low": f"bold {palette.sev_low}",
            "sev.info": palette.sev_none,
            "sev.none": palette.sev_none,
            "label.research": f"bold {palette.secondary}",
            "label.poc": f"bold {palette.warning}",
            "label.unverified": palette.muted,
            "label.patch": f"bold {palette.success}",
            "repr.number": palette.info,
            "repr.str": palette.success,
        }
    )


def detect_system_theme(env: dict[str, str] | None = None) -> str:
    """Best-effort terminal background detection via ``COLORFGBG``."""
    env = dict(os.environ) if env is None else env
    value = env.get("COLORFGBG", "")
    if value:
        try:
            background = int(value.split(";")[-1])
        except ValueError:
            return DARK
        return LIGHT if background in (7, 15) else DARK
    return DARK


def resolve_theme_name(preference: str | None) -> str:
    choice = (preference or "").strip().lower()
    if choice in ("dark", DARK):
        return DARK
    if choice in ("light", LIGHT):
        return LIGHT
    return detect_system_theme()


def preferred_theme_name() -> str:
    """Theme from env (CVELI_THEME) > saved user setting > system > dark."""
    from config.settings import get_settings

    env_choice = get_settings().theme
    if env_choice:
        return resolve_theme_name(env_choice)
    try:
        from storage.system_repositories import SettingsRepository

        return resolve_theme_name(SettingsRepository().get("theme", "auto"))
    except Exception:
        return DARK


def register_themes(app) -> None:
    for palette in PALETTES.values():
        app.register_theme(to_textual_theme(palette))


def apply_theme(app, name: str | None = None) -> str:
    """Register Opus themes on ``app`` and activate the preferred one."""
    register_themes(app)
    chosen = name or preferred_theme_name()
    app.theme = chosen
    return chosen


SEVERITY_SYMBOLS = {
    "CRITICAL": "◆",
    "HIGH": "▲",
    "MEDIUM": "●",
    "LOW": "▽",
    "INFO": "·",
    "N/A": "–",
}
