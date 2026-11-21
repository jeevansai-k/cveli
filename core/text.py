"""Text hygiene for untrusted feed data shown in a terminal."""

from __future__ import annotations

import re

# CSI / OSC / other ESC sequences, then remaining C0/C1 controls except \n and \t.
_ANSI_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)"  # OSC ... BEL/ST (hyperlinks, titles)
    r"|\x1b\[[0-?]*[ -/]*[@-~]"  # CSI
    r"|\x1b[@-Z\\-_]"  # 2-byte ESC sequences
)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def sanitize_terminal_text(value: str | None, keep_newlines: bool = True) -> str:
    """Strip ANSI escape sequences and control characters from feed text."""
    if not value:
        return ""
    text = _ANSI_RE.sub("", str(value))
    text = _CONTROL_RE.sub("", text)
    if not keep_newlines:
        text = re.sub(r"[\r\n\t]+", " ", text)
    return text.strip()


def one_line(value: str | None, limit: int | None = None) -> str:
    text = re.sub(r"\s+", " ", sanitize_terminal_text(value)).strip()
    if limit and len(text) > limit:
        return text[: max(0, limit - 1)] + "…"
    return text


def has_control_chars(text: str) -> bool:
    """True if ``text`` contains any Unicode control/format characters."""
    import unicodedata

    return any(unicodedata.category(ch).startswith("C") for ch in text)
