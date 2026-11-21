"""
CISA Known Exploited Vulnerabilities (KEV) adapter.

Purpose: Flag CVEs that CISA lists as known exploited in the wild.
Outputs: CVEModel objects with ``kev=True`` (no CVSS/EPSS is invented).
"""

from __future__ import annotations

import json
from typing import Any

from core.models import CVEModel
from core.text import sanitize_terminal_text
from sources.base import BaseAdapter
from utils.logger import get_logger

log = get_logger(__name__)

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CISA_KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


class CISAKEVAdapter(BaseAdapter):
    """Adapter for CISA Known Exploited Vulnerabilities (KEV) Catalog."""

    name = "cisa_kev"
    endpoint = "CISA KEV"

    def fetch(self, query_params: dict[str, Any] | None = None) -> str:
        """Fetch raw CISA KEV catalog feed JSON."""
        return self.http.get(CISA_KEV_URL).text

    def parse(self, raw_data: str | bytes) -> list[dict[str, Any]]:
        try:
            data = json.loads(raw_data)
        except (TypeError, ValueError) as error:
            log.error(f"Failed to parse CISA KEV JSON: {error}")
            return []
        items = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        return [item for item in items if isinstance(item, dict)]

    def normalize(self, record: dict[str, Any]) -> dict[str, Any]:
        cve_id = str(record.get("cveID", "")).strip().upper()
        if not cve_id.startswith("CVE-"):
            raise ValueError("CISA KEV record missing valid CVE ID")
        vendor = sanitize_terminal_text(record.get("vendorProject", ""))
        product = sanitize_terminal_text(record.get("product", ""))
        refs = [
            value
            for value in (record.get("notes"), record.get("source"))
            if isinstance(value, str) and value.startswith(("http://", "https://"))
        ]
        return {
            "id": cve_id,
            "summary": sanitize_terminal_text(record.get("shortDescription", "")),
            "severity": None,
            "cvss": None,
            "vector": None,
            "published": "",
            "updated": "",
            "kev_date": str(record.get("dateAdded", ""))[:10],
            "affected_products": [
                {"name": f"{vendor}/{product}" if vendor else product, "version": "*"}
            ],
            "references": refs or [CISA_KEV_CATALOG_URL],
            "exploit_available": True,
            "kev": True,
            "epss": None,
            "vendor": vendor or None,
            "cwe": None,
            "tags": ["cisa_kev", "actively_exploited"],
            "sources": ["CISA KEV"],
        }

    def fetch_and_normalize(
        self, query_params: dict[str, Any] | None = None
    ) -> list[CVEModel]:
        raw = self.fetch(query_params=query_params)
        models = []
        for rec in self.parse(raw):
            try:
                models.append(CVEModel(**self.normalize(rec)))
            except Exception as error:
                log.warning(f"Skipping malformed KEV record: {error}")
        return models
