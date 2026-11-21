"""
CVE Record Formatter.

Purpose: Render CVE (and Exploit-DB) records as Rich tables/panels, JSON,
Markdown or plain text for the CLI and exports.
Security: every feed-provided string is passed through
``core.text.sanitize_terminal_text`` and inserted as ``rich.text.Text`` (never
parsed as markup), so feed data cannot inject Rich markup or terminal escapes.
Colours come from Opus 5.5 tokens (``cli.tui.theme.style``); severity is always
shown as text + symbol, never colour alone.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

from rich.console import Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from core.models import CVEModel, ExploitModel
from core.text import one_line, sanitize_terminal_text

NVD_CVE_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"
CVE_ORG_RECORD_URL = "https://www.cve.org/CVERecord?id={cve_id}"
CISA_KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
SAFE_URL_SCHEMES = {"http", "https"}
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$")
URL_PATTERN = re.compile(r"https?://[^\s;,<>\"'`]+")
CVEInput = CVEModel | dict[str, Any]

SEVERITY_SYMBOLS = {
    "CRITICAL": "◆",
    "HIGH": "▲",
    "MEDIUM": "●",
    "LOW": "▽",
    "INFO": "·",
    "N/A": "–",
}


def style(token: str) -> str:
    from cli.tui.theme import style as theme_style

    return theme_style(token)


def _to_dict(item: CVEInput) -> dict[str, Any]:
    return item.to_dict() if isinstance(item, CVEModel) else item


def format_epss(epss: float | int | None) -> str:
    if epss is None:
        return "N/A"
    try:
        value = float(epss)
    except (TypeError, ValueError):
        return "N/A"
    return f"{value * 100:.1f}%"


def format_cvss(cvss: float | int | None) -> str:
    if cvss is None:
        return "N/A"
    try:
        return f"{float(cvss):.1f}"
    except (TypeError, ValueError):
        return "N/A"


def severity_label(severity: str | None) -> str:
    sev = (severity or "N/A").upper()
    return f"{SEVERITY_SYMBOLS.get(sev, '–')} {sev}"


def severity_text(severity: str | None) -> Text:
    sev = (severity or "N/A").upper()
    token = f"sev.{sev.lower()}" if sev != "N/A" else "sev.none"
    return Text(severity_label(sev), style=style(token))


def build_known_reference_urls(cve_id: str) -> list[tuple[str, str]]:
    if not CVE_ID_PATTERN.match(cve_id):
        return []
    return [
        ("NVD", NVD_CVE_URL.format(cve_id=cve_id)),
        ("CVE.org", CVE_ORG_RECORD_URL.format(cve_id=cve_id)),
    ]


def is_safe_reference_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in SAFE_URL_SCHEMES and bool(parsed.netloc)


def extract_reference_urls(reference: str) -> list[str]:
    return [url.rstrip(").]") for url in URL_PATTERN.findall(reference)]


def build_reference_items(cve: CVEInput) -> list[tuple[str, str]]:
    data = _to_dict(cve)
    cve_id = str(data.get("id", "")).strip()
    urls: list[tuple[str, str]] = build_known_reference_urls(cve_id) if cve_id else []
    if data.get("kev") or (
        data.get("exploit_available") and "cisa_kev" in data.get("tags", [])
    ):
        urls.append(("CISA KEV Catalog", CISA_KEV_CATALOG_URL))

    extras = [
        url
        for ref in data.get("references", [])
        if isinstance(ref, str)
        for url in extract_reference_urls(ref)
        if is_safe_reference_url(url)
    ]
    seen = {url for _, url in urls}
    for index, url in enumerate(extras, start=1):
        if url in seen:
            continue
        host = urlparse(url).netloc.replace("www.", "")
        urls.append((host or f"Reference {index}", url))
        seen.add(url)
    return urls


def _link_text(url: str) -> Text:
    return Text(url, style=f"link {url}")


def _reference_renderables(items: Iterable[tuple[str, str]]) -> list[Text]:
    lines: list[Text] = []
    for label, url in items:
        lines.append(Text(f"• {label}", style="bold"))
        line = Text("  ")
        line.append_text(_link_text(url))
        lines.append(line)
    return lines


def kev_status(data: dict[str, Any]) -> str:
    kev = data.get("kev") or (
        data.get("exploit_available") and "cisa_kev" in data.get("tags", [])
    )
    return "YES" if kev else "NO"


def format_cve_table(cves: list[CVEInput], title: str = "CVE Search Results") -> Table:
    """Format a list of CVE objects into a Rich Console Table."""
    table = Table(
        title=title, expand=True, header_style=style("title"), border_style="dim"
    )
    table.add_column("#", justify="right", width=3, no_wrap=True)
    table.add_column("CVE ID", style=style("cve.id"), no_wrap=True, width=16)
    table.add_column("Severity", width=11, no_wrap=True)
    table.add_column("CVSS", justify="right", width=5)
    table.add_column("EPSS", justify="right", width=6)
    table.add_column("KEV", width=4)
    table.add_column("Vendor", width=14)
    table.add_column("Published", style=style("muted"), width=10)
    table.add_column("Summary")

    for index, item in enumerate(cves, start=1):
        data = _to_dict(item)
        table.add_row(
            str(index),
            Text(str(data.get("id", "N/A"))),
            severity_text(data.get("severity")),
            format_cvss(data.get("cvss")),
            format_epss(data.get("epss")),
            Text(kev_status(data)),
            Text(one_line(data.get("vendor") or "N/A", 14)),
            str(data.get("published", "") or "N/A")[:10],
            Text(one_line(data.get("summary") or "N/A", 80)),
        )
    return table


def format_cve_detail_panel(
    cve: CVEInput, exploits: list[ExploitModel] | None = None
) -> Panel:
    """Format a single CVE into a detailed Rich Panel view."""
    data = _to_dict(cve)

    cve_id = str(data.get("id", "N/A"))
    vector = data.get("vector") or "N/A"
    kev_date = data.get("kev_date") or "N/A"
    summary = sanitize_terminal_text(data.get("summary") or "N/A")
    products = data.get("affected_products") or []
    cwe = data.get("cwe")

    metadata = Table.grid(padding=(0, 1))
    metadata.add_column(style="bold", width=16)
    metadata.add_column()
    metadata.add_row("Severity", severity_text(data.get("severity")))
    metadata.add_row("CVSS", format_cvss(data.get("cvss")))
    metadata.add_row("EPSS", format_epss(data.get("epss")))
    metadata.add_row("EPSS Percentile", format_epss(data.get("epss_percentile")))
    metadata.add_row("Vendor", Text(one_line(data.get("vendor") or "N/A")))
    metadata.add_row("Published", str(data.get("published") or "N/A"))
    metadata.add_row("Modified", str(data.get("updated") or "N/A"))
    metadata.add_row("CISA KEV", kev_status(data))
    if kev_date != "N/A":
        metadata.add_row("KEV Date", str(kev_date))
    count = int(data.get("public_exploit_count") or 0)
    if exploits is not None:
        count = len(exploits)
    metadata.add_row("Public exploits", f"{count} Exploit-DB reference(s)")
    if cwe:
        cwe_text = (
            f"CWE-{cwe.get('id')}: {cwe.get('name')}"
            if isinstance(cwe, dict)
            else str(cwe)
        )
        metadata.add_row("CWE", Text(cwe_text))
    if vector != "N/A":
        metadata.add_row("Vector", Text(str(vector)))
    if data.get("sources"):
        metadata.add_row("Sources", Text(", ".join(data["sources"])))

    blocks: list[Any] = [
        metadata,
        Text(),
        Text("Description", style="bold"),
        Rule(style="dim"),
        Text(summary),
    ]

    if products:
        blocks.extend(
            [
                Text(),
                Text("Affected Products / Versions", style="bold"),
                Rule(style="dim"),
            ]
        )
        for product in products:
            name = product.get("name") if isinstance(product, dict) else str(product)
            version = product.get("version", "") if isinstance(product, dict) else ""
            blocks.append(Text(one_line(f"• {name} {version}".rstrip())))

    if exploits:
        from core.safety import EXPLOIT_NOTICE, EXPLOITDB_ATTRIBUTION

        blocks.extend(
            [Text(), Text("Public exploit references", style="bold"), Rule(style="dim")]
        )
        for exploit in exploits:
            blocks.append(exploit_line(exploit))
        blocks.append(Text(EXPLOIT_NOTICE, style=style("warning")))
        blocks.append(Text(EXPLOITDB_ATTRIBUTION, style=style("muted")))

    ref_items = build_reference_items(data)
    if ref_items:
        blocks.extend(
            [
                Text(),
                Text("References", style="bold"),
                Rule(style="dim"),
                *_reference_renderables(ref_items),
            ]
        )

    return Panel(
        Group(*blocks),
        title=Text(cve_id, style="bold"),
        border_style=style("accent"),
        expand=True,
    )


def _md_escape(text: str) -> str:
    return re.sub(r"([\\`*_{}\[\]<>()#+!|])", r"\\\1", one_line(text))


def format_cve_markdown(cves: list[CVEInput]) -> str:
    """Format CVE records into a Markdown document string."""
    lines = ["# CVE Vulnerability Report", ""]
    for item in cves:
        d = _to_dict(item)
        lines.append(f"## {_md_escape(str(d.get('id', 'N/A')))}")
        lines.append(
            f"- **Severity:** {d.get('severity') or 'N/A'} "
            f"(CVSS {format_cvss(d.get('cvss'))})"
        )
        lines.append(f"- **Vendor:** {_md_escape(d.get('vendor') or 'N/A')}")
        lines.append(f"- **Published:** {d.get('published') or 'N/A'}")
        lines.append(f"- **EPSS:** {format_epss(d.get('epss'))}")
        lines.append(f"- **CISA KEV:** {kev_status(d)}")
        exploit_count = int(d.get("public_exploit_count") or 0)
        lines.append(f"- **Public exploit references:** {exploit_count}")
        lines.append("")
        lines.append("### Description")
        lines.append(_md_escape(d.get("summary") or "N/A"))
        lines.append("")
        refs = [
            url
            for ref in d.get("references", [])
            if isinstance(ref, str)
            for url in extract_reference_urls(ref)
            if is_safe_reference_url(url)
        ]
        if refs:
            lines.append("### References")
            lines.extend(f"- <{url}>" for url in dict.fromkeys(refs))
            lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)


def format_cve_json(cves: list[CVEInput], indent: int = 2) -> str:
    data = [_to_dict(item) for item in cves]
    return json.dumps(data, indent=indent, default=str)


# --- Exploit-DB -------------------------------------------------------------


def exploit_line(exploit: ExploitModel) -> Text:
    line = Text("• ")
    line.append(f"EDB-{exploit.edb_id}", style=style("cve.id"))
    line.append(f"  {one_line(exploit.title, 90)}")
    line.append(
        f"\n  {exploit.date_published or 'N/A'} · {exploit.platform or 'N/A'} · "
        f"{exploit.type or 'N/A'} · {one_line(exploit.author or 'N/A', 40)} · "
        f"{'verified' if exploit.verified else 'unverified'}",
        style=style("muted"),
    )
    if exploit.source_url:
        line.append("\n  ")
        line.append_text(_link_text(exploit.source_url))
    return line


def format_exploit_table(
    exploits: list[ExploitModel], title: str = "Exploit-DB references"
) -> Table:
    table = Table(
        title=title, expand=True, header_style=style("title"), border_style="dim"
    )
    table.add_column("EDB-ID", style=style("cve.id"), no_wrap=True, width=8)
    table.add_column("Date", width=10, style=style("muted"))
    table.add_column("Platform", width=10)
    table.add_column("Type", width=8)
    table.add_column("Verified", width=8)
    table.add_column("CVE", width=16)
    table.add_column("Title")
    for exploit in exploits:
        table.add_row(
            str(exploit.edb_id),
            exploit.date_published or "N/A",
            Text(exploit.platform or "N/A"),
            Text(exploit.type or "N/A"),
            "✓ yes" if exploit.verified else "✗ no",
            Text(", ".join(exploit.cve_ids[:2]) or "N/A"),
            Text(one_line(exploit.title, 90)),
        )
    return table


def format_exploit_detail_panel(exploit: ExploitModel) -> Panel:
    from core.safety import EXPLOIT_NOTICE, EXPLOITDB_ATTRIBUTION

    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="bold", width=16)
    grid.add_column()
    rows = [
        ("EDB-ID", str(exploit.edb_id)),
        ("CVE IDs", ", ".join(exploit.cve_ids) or "N/A"),
        ("Published", exploit.date_published or "N/A"),
        ("Updated", exploit.date_updated or "N/A"),
        ("Author", exploit.author or "N/A"),
        ("Platform", exploit.platform or "N/A"),
        ("Type", exploit.type or "N/A"),
        ("Port", str(exploit.port) if exploit.port else "N/A"),
        ("Verified", "yes" if exploit.verified else "no"),
        ("Product", exploit.affected_product or "N/A"),
        ("Versions", ", ".join(exploit.affected_versions) or "N/A"),
        ("Tags", ", ".join(exploit.tags) or "N/A"),
        ("Licence", exploit.license or "N/A"),
    ]
    for key, value in rows:
        grid.add_row(key, Text(one_line(value)))
    labels = Text()
    for label in exploit.safety_labels:
        from core.safety import label_style

        labels.append(f"[{label}] ", style=style(label_style(label)))
    blocks: list[Any] = [
        Text(one_line(exploit.title), style="bold"),
        labels,
        Text(),
        grid,
        Text(),
        Text("Description", style="bold"),
        Text(one_line(exploit.description) if exploit.description else "N/A"),
        Text(),
        Text("Source", style="bold"),
    ]
    for label, url in (
        ("Exploit-DB entry", exploit.source_url),
        ("Original advisory", exploit.advisory_url),
    ):
        if url and is_safe_reference_url(url):
            line = Text(f"• {label}: ")
            line.append_text(_link_text(url))
            blocks.append(line)
    if exploit.file_url:
        blocks.append(
            Text(
                "• Exploit code is not downloaded or displayed by CVELI. "
                f"Repository path: {exploit.file_path}",
                style=style("muted"),
            )
        )
    blocks.extend(
        [
            Text(),
            Text(EXPLOIT_NOTICE, style=style("warning")),
            Text(EXPLOITDB_ATTRIBUTION, style=style("muted")),
        ]
    )
    return Panel(
        Group(*blocks),
        title=Text(f"EDB-{exploit.edb_id}", style="bold"),
        border_style=style("accent"),
        expand=True,
    )
