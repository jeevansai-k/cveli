"""
CVE Record Formatter.

Purpose: Format single or multiple CVE objects into various output formats.
Inputs: CVEModel objects or dictionaries, format type string.
Outputs: Rich Table, JSON string, Markdown text, or Plain Text.
Responsibilities: Presentation rendering for CLI terminal and export services.
Dependencies: rich, core.models.CVEModel, utils.helpers.
"""

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

from core.models import CVEModel

NVD_CVE_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"
CVE_ORG_RECORD_URL = "https://www.cve.org/CVERecord?id={cve_id}"
CISA_KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
SAFE_URL_SCHEMES = {"http", "https"}
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$")
URL_PATTERN = re.compile(r"https?://[^\s;,]+")
CVEInput = CVEModel | dict[str, Any]


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
    if data.get("exploit_available") and "cisa_kev" in data.get("tags", []):
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
        label = host or f"Reference {index}"
        urls.append((label, url))
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


def format_cve_table(cves: list[CVEInput], title: str = "CVE Search Results") -> Table:
    """Format a list of CVE objects into a Rich Console Table."""
    table = Table(title=title, expand=True, highlight=True)

    table.add_column("#", justify="right", width=3, no_wrap=True)
    table.add_column("CVE ID", style="cyan bold", no_wrap=True, width=16)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("CVSS", justify="right", width=6)
    table.add_column("EPSS", justify="right", width=7)
    table.add_column("Vendor", style="magenta", width=14)
    table.add_column("Published", style="dim", width=11)
    table.add_column("Summary", style="white")

    severity_colors = {
        "CRITICAL": "bold bright_magenta",
        "HIGH": "bold bright_red",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
        "INFO": "blue",
    }

    for index, item in enumerate(cves, start=1):
        cve_dict = _to_dict(item)

        cve_id = str(cve_dict.get("id", "N/A"))
        severity = str(cve_dict.get("severity") or "N/A").upper()
        cvss = format_cvss(cve_dict.get("cvss"))
        epss = format_epss(cve_dict.get("epss"))
        vendor = str(cve_dict.get("vendor") or "N/A")
        published = str(cve_dict.get("published", "") or "N/A")[:10]
        summary = str(cve_dict.get("summary", "") or "N/A")

        if len(summary) > 80:
            summary = summary[:77] + "..."

        sev_style = severity_colors.get(severity, "white")
        sev_text = Text(severity, style=sev_style)

        table.add_row(
            str(index),
            cve_id,
            sev_text,
            cvss,
            epss,
            vendor,
            published,
            summary,
        )

    return table


def format_cve_detail_panel(cve: CVEInput) -> Panel:
    """Format a single CVE into a detailed Rich Panel view."""
    data = _to_dict(cve)

    cve_id = data.get("id", "N/A")
    severity = str(data.get("severity") or "N/A").upper()
    cvss = format_cvss(data.get("cvss"))
    vector = data.get("vector") or "N/A"
    vendor = data.get("vendor") or "N/A"
    published = data.get("published") or "N/A"
    updated = data.get("updated") or "N/A"
    kev_date = data.get("kev_date") or "N/A"
    summary = data.get("summary") or "N/A"
    products = data.get("affected_products") or []
    cwe = data.get("cwe")

    metadata = Table.grid(padding=(0, 1))
    metadata.add_column(style="bold", width=12)
    metadata.add_column()
    metadata.add_row("Severity", severity)
    metadata.add_row("CVSS", cvss)
    metadata.add_row("EPSS", format_epss(data.get("epss")))
    metadata.add_row("Vendor", str(vendor))
    metadata.add_row("Published", str(published))
    metadata.add_row("Modified", str(updated))
    kev_status = (
        "YES"
        if data.get("exploit_available") and "cisa_kev" in data.get("tags", [])
        else "NO"
    )
    metadata.add_row("CISA KEV", kev_status)
    if kev_date != "N/A":
        metadata.add_row("KEV Date", str(kev_date))
    if cwe:
        cwe_text = (
            f"CWE-{cwe.get('id')}: {cwe.get('name')}"
            if isinstance(cwe, dict)
            else str(cwe)
        )
        metadata.add_row("CWE", cwe_text)
    if vector != "N/A":
        metadata.add_row("Vector", str(vector))
    if data.get("sources"):
        metadata.add_row("Sources", ", ".join(data["sources"]))

    blocks: list[Any] = [
        metadata,
        Text(),
        Text("Description", style="bold"),
        Rule(style="dim"),
        Text(str(summary)),
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
            blocks.append(Text(f"• {name} {version}".rstrip()))

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
        title=f"[bold]{cve_id}[/bold]",
        border_style="cyan",
        expand=True,
    )


def format_cve_markdown(cves: list[CVEInput]) -> str:
    """Format CVE records into Markdown document string."""
    lines = ["# CVE Vulnerability Report", ""]
    for item in cves:
        d = item.to_dict() if isinstance(item, CVEModel) else item
        lines.append(f"## {d.get('id', 'N/A')}")
        lines.append(
            f"- **Severity:** {d.get('severity', 'Info')} "
            f"(CVSS {format_cvss(d.get('cvss'))})"
        )
        lines.append(f"- **Vendor:** {d.get('vendor') or 'N/A'}")
        lines.append(f"- **Published:** {d.get('published') or 'N/A'}")
        lines.append(f"- **EPSS:** {format_epss(d.get('epss'))}")
        lines.append("")
        lines.append(f"### Description\n{d.get('summary', '')}\n")

        refs = d.get("references", [])
        if refs:
            lines.append("### References")
            for r in refs:
                lines.append(f"- [{r}]({r})")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def format_cve_json(cves: list[CVEInput], indent: int = 2) -> str:
    """Format CVE records into JSON string."""
    data = [item.to_dict() if isinstance(item, CVEModel) else item for item in cves]
    return json.dumps(data, indent=indent, default=str)
