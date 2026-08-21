"""
Vendor and Threat Intelligence Adapters.

Purpose: Fetch vendor advisories and threat intelligence feeds.
Inputs: Query filters.
Outputs: Normalized list of CVEModel objects with exploit availability flagged.
Responsibilities: Parse CISA KEV JSON feed and flag known exploited vulnerabilities.
Dependencies: httpx, sources.base.BaseAdapter, core.models.CVEModel.
"""

from typing import Any

import httpx

from core.models import CVEModel
from sources.base import BaseAdapter
from utils.errors import NetworkError
from utils.logger import get_logger

log = get_logger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


class CISAKEVAdapter(BaseAdapter):
    """Adapter for CISA Known Exploited Vulnerabilities (KEV) Catalog."""

    name = "cisa_kev"

    def __init__(self, api_key: str | None = None, timeout: int = 30):
        super().__init__(api_key=api_key, timeout=timeout)
        self.headers = {"User-Agent": "cveli/0.1.0"}

    def fetch(self, query_params: dict[str, Any] | None = None) -> str:
        """Fetch raw CISA KEV catalog feed JSON."""
        try:
            with httpx.Client(
                timeout=float(self.timeout), follow_redirects=True
            ) as client:
                response = client.get(CISA_KEV_URL, headers=self.headers)
                if response.status_code != 200:
                    raise NetworkError(
                        endpoint="CISA KEV",
                        status=response.status_code,
                        message=(
                            "CISA KEV catalog feed returned status "
                            f"{response.status_code}"
                        ),
                    )
                return response.text
        except httpx.HTTPError as e:
            raise NetworkError(
                endpoint="CISA KEV", message=f"HTTP request to CISA KEV failed: {e}"
            ) from e

    def parse(self, raw_data: str) -> list[dict[str, Any]]:
        """Parse CISA KEV JSON catalog into vulnerability list."""
        import json

        try:
            data = json.loads(raw_data)
            return data.get("vulnerabilities", [])
        except Exception as e:
            log.error(f"Failed to parse CISA KEV JSON: {e}")
            return []

    def normalize(self, record: dict[str, Any]) -> dict[str, Any]:
        """Normalize a single CISA KEV item into canonical CVE format."""
        cve_id = str(record.get("cveID", "")).strip().upper()
        if not cve_id.startswith("CVE-"):
            raise ValueError("CISA KEV record missing valid CVE ID")
        vendor = record.get("vendorProject", "")
        product = record.get("product", "")
        summary = record.get("shortDescription", "")
        date_added = record.get("dateAdded", "")[:10]

        products = [
            {"name": f"{vendor}/{product}" if vendor else product, "version": "*"}
        ]
        refs = [
            value
            for value in (record.get("notes"), record.get("source"))
            if isinstance(value, str) and value.startswith("http")
        ]

        return {
            "id": cve_id,
            "summary": summary,
            "severity": None,
            "cvss": None,
            "vector": None,
            "published": "",
            "updated": "",
            "kev_date": date_added,
            "affected_products": products,
            "references": refs or [CISA_KEV_CATALOG_URL],
            "exploit_available": True,
            "epss": None,
            "vendor": vendor,
            "cwe": None,
            "tags": ["cisa_kev", "actively_exploited"],
            "sources": ["CISA KEV"],
        }

    def fetch_and_normalize(
        self, query_params: dict[str, Any] | None = None
    ) -> list[CVEModel]:
        """Fetch and return list of CVEModel with exploit_available=True."""
        try:
            raw = self.fetch(query_params=query_params)
            records = self.parse(raw)
            models = []
            for rec in records:
                norm_dict = self.normalize(rec)
                models.append(CVEModel(**norm_dict))
            return models
        except Exception as e:
            log.warning(f"CISA KEV fetch failed: {e}")
            return []
