"""
CVE.org API Source Adapter.

Purpose: Fetch official CVE JSON records from CVE.org API v5.
Inputs: CVE ID or search parameters.
Outputs: Normalized list of CVEModel objects.
Responsibilities: Fetch CVE JSON v5 records from CVE.org, normalize metadata.
Dependencies: httpx, sources.base.BaseAdapter, core.models.CVEModel.
"""

from typing import Any

import httpx

from core.models import CVEModel
from sources.base import BaseAdapter
from utils.errors import NetworkError
from utils.logger import get_logger

log = get_logger(__name__)

CVE_ORG_API_URL = "https://cveawg.mitre.org/api/cve"


class CVEOrgAdapter(BaseAdapter):
    """Adapter for official CVE.org v5 API."""

    name = "cve_org"

    def __init__(self, api_key: str | None = None, timeout: int = 30):
        super().__init__(api_key=api_key, timeout=timeout)
        self.headers = {"User-Agent": "cveli/0.1.0"}

    def fetch(self, query_params: dict[str, Any] | None = None) -> str:
        """Fetch a specific CVE record from CVE.org API v5."""
        params = query_params or {}
        cve_id = params.get("cve_id", "").strip().upper()

        if not cve_id:
            raise NetworkError(
                endpoint="CVE.org",
                message="cve_id parameter required for CVE.org fetch",
            )

        url = f"{CVE_ORG_API_URL}/{cve_id}"

        try:
            with httpx.Client(
                timeout=float(self.timeout), follow_redirects=True
            ) as client:
                response = client.get(url, headers=self.headers)
                if response.status_code != 200:
                    raise NetworkError(
                        endpoint="CVE.org",
                        status=response.status_code,
                        message=f"CVE.org API returned status {response.status_code}",
                    )
                return response.text
        except httpx.HTTPError as e:
            raise NetworkError(
                endpoint="CVE.org", message=f"HTTP request to CVE.org failed: {e}"
            ) from e

    def parse(self, raw_data: str) -> list[dict[str, Any]]:
        """Parse raw CVE.org JSON v5 format."""
        import json

        try:
            data = json.loads(raw_data)
            return [data] if "cveMetadata" in data or "containers" in data else []
        except Exception as e:
            log.error(f"Failed to parse CVE.org JSON: {e}")
            return []

    def normalize(self, record: dict[str, Any]) -> dict[str, Any]:
        """Normalize CVE.org JSON v5 format into canonical CVE record."""
        meta = record.get("cveMetadata", {})
        cve_id = str(meta.get("cveId", "")).strip().upper()
        if not cve_id.startswith("CVE-"):
            raise ValueError("CVE.org record missing valid CVE ID")

        containers = record.get("containers", {})
        cna = containers.get("cna", {})

        # Title/Description
        title = cna.get("title", "")
        descriptions = cna.get("descriptions", [])
        summary = title or ""
        for d in descriptions:
            if d.get("lang") == "en":
                summary = d.get("value", summary)
                break

        # CVSS Metrics
        metrics = cna.get("metrics", [])
        cvss_score = None
        severity = None
        vector = None

        for m in metrics:
            if "cvssV3_1" in m:
                v = m["cvssV3_1"]
                cvss_score = float(v["baseScore"])
                severity = str(v.get("baseSeverity", "")).capitalize() or None
                vector = v.get("vectorString")
                break
            elif "cvssV3_0" in m:
                v = m["cvssV3_0"]
                cvss_score = float(v["baseScore"])
                severity = str(v.get("baseSeverity", "")).capitalize() or None
                vector = v.get("vectorString")
                break

        # Affected products & vendors
        products = []
        affected = cna.get("affected", [])
        for aff in affected:
            v_name = aff.get("vendor", "")
            p_name = aff.get("product", "")
            versions = [ver.get("version", "*") for ver in aff.get("versions", [])]
            ver_str = ", ".join(versions[:3]) if versions else "*"
            products.append(
                {"name": f"{v_name}/{p_name}" if v_name else p_name, "version": ver_str}
            )

        vendor = affected[0].get("vendor") if affected else None

        # References
        refs = [r.get("url") for r in cna.get("references", []) if r.get("url")]

        published = meta.get("datePublished", "")[:10]
        updated = meta.get("dateUpdated", "")[:10]

        return {
            "id": cve_id,
            "summary": summary,
            "severity": severity
            if severity in ["Critical", "High", "Medium", "Low", "Info"]
            else None,
            "cvss": cvss_score,
            "vector": vector,
            "published": published,
            "updated": updated,
            "affected_products": products,
            "references": refs,
            "exploit_available": False,
            "epss": None,
            "vendor": vendor,
            "cwe": None,
            "tags": [],
            "sources": ["CVE.org"],
        }

    def fetch_and_normalize(
        self, query_params: dict[str, Any] | None = None
    ) -> list[CVEModel]:
        """Fetch from CVE.org and normalize into CVEModel list."""
        try:
            raw = self.fetch(query_params=query_params)
            records = self.parse(raw)
            models = []
            for rec in records:
                norm_dict = self.normalize(rec)
                models.append(CVEModel(**norm_dict))
            return models
        except Exception as e:
            log.warning(f"CVE.org fetch failed: {e}")
            return []
