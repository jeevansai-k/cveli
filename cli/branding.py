"""Shared CVELI branding helpers for CLI and TUI surfaces."""

SAGE_GREEN = "#9caf88"
SAGE_GREEN_ANSI = "\033[38;2;156;175;136m"
ANSI_RESET = "\033[0m"

CVELI_ART = """\
 ██████╗██╗   ██╗███████╗██╗     ██╗
██╔════╝██║   ██║██╔════╝██║     ██║
██║     ██║   ██║█████╗  ██║     ██║
██║     ╚██╗ ██╔╝██╔══╝  ██║     ██║
╚██████╗ ╚████╔╝ ███████╗███████╗██║
 ╚═════╝  ╚═══╝  ╚══════╝╚══════╝╚═╝"""

SUBTITLE = "created by jeevansai-k"


def brand_text(extra: str = "") -> str:
    parts = [CVELI_ART, "", "                 CVELI", f"          {SUBTITLE}"]
    if extra:
        parts.extend(["", extra])
    return "\n".join(parts)


def brand_ansi(extra: str = "") -> str:
    return f"\b\n{SAGE_GREEN_ANSI}{brand_text(extra)}{ANSI_RESET}"


APP_HELP = brand_ansi("Professional, extensible search-first CVE CLI/TUI tool.")

SEARCH_HELP = brand_ansi(
    "\n".join(
        [
            "Search live CVE sources with local cache fallback.",
            "Default publication range: last 1 year.",
            "Use --range for 1m, 3m, 6m, 9m, 1y, 2y, 3y, 4y, 5y, complete.",
            "Examples:",
            "  cveli search http",
            "  cveli search CVE-2025-32756",
            "  cveli search fortinet --range 5y",
            "  cveli search openssl --cache",
        ]
    )
)

EXPORT_HELP = brand_ansi(
    "\n".join(
        [
            "Export stored CVE records from the local cveli database.",
            "Formats: json, csv, markdown, txt.",
            "Filters: optional query, --severity, --limit.",
            "Examples:",
            "  cveli export openssl --output openssl.json --format json",
            "  cveli export fortinet --output fortinet.csv --format csv",
            "  cveli export --severity High --output high.md --format markdown",
            "  cveli export http --output http.txt --format txt",
        ]
    )
)
