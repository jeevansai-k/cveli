"""
Ruby-safe escaping for untrusted feed text placed into generated templates.

Feed data (CVE summaries, Exploit-DB titles, author names, URLs) must never be
able to break out of a string literal or comment and inject Ruby code.
"""

from __future__ import annotations

import re
import textwrap

from core.text import one_line, sanitize_terminal_text

_SAFE_REF_RE = re.compile(r"^[A-Za-z0-9._:/?#\[\]@!$&()*+,;=%~-]+$")


def ruby_single(value: str | None, limit: int = 200) -> str:
    """Contents for a single-quoted Ruby string (``'...'``)."""
    text = one_line(value or "", limit)
    return text.replace("\\", "\\\\").replace("'", "\\'")


def ruby_q_block(value: str | None, width: int = 72, indent: str = "        ") -> str:
    """Body for a ``%q{...}`` literal: braces/backslashes neutralised, wrapped."""
    text = sanitize_terminal_text(value or "", keep_newlines=False)
    text = text.replace("\\", "/").replace("{", "(").replace("}", ")")
    lines = textwrap.wrap(text, width=width) or [""]
    return "\n".join(f"{indent}{line}" for line in lines)


def ruby_comment(value: str | None, limit: int = 160) -> str:
    """Single-line comment text (newlines removed so it cannot end the comment)."""
    return one_line(value or "", limit)


def safe_reference_url(url: str) -> str | None:
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")) or not _SAFE_REF_RE.match(url):
        return None
    return url


def module_slug(*parts: str) -> str:
    slug = "_".join(
        re.sub(r"[^a-z0-9]+", "_", p.lower()).strip("_") for p in parts if p
    )
    return re.sub(r"_+", "_", slug)[:80] or "cveli_research_template"
