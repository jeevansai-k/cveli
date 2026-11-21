"""
NVD API 2.0 Source Adapter.

Purpose: Fetch and normalize vulnerability records from NVD.
Inputs: Query parameters (cve_id, keyword, severity, date range, pagination).
Outputs: List of canonical CVEModel objects.
Responsibilities: Fetch NVD API 2.0 JSON and normalize fields.
Dependencies: httpx, sources.base.BaseAdapter, core.models.CVEModel, utils.logger.
"""

from typing import Any

import httpx

from config.version import USER_AGENT
from core.models import CWEID, CVEModel
from sources.base import BaseAdapter
from utils.errors import NetworkError
from utils.logger import get_logger

log = get_logger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDAdapter(BaseAdapter):
    """Adapter for National Vulnerability Database (NVD) API 2.0."""

    name = "nvd"

    def __init__(self, api_key: str | None = None, timeout: int = 30):
        super().__init__(api_key=api_key, timeout=timeout)
        self.headers = {"User-Agent": USER_AGENT}
        if self.api_key:
            self.headers["apiKey"] = self.api_key

    def fetch(self, query_params: dict[str, Any] | None = None) -> str:
        """Fetch raw JSON payload from NVD API 2.0."""
        params = query_params or {}
        req_params: dict[str, Any] = {}

        if "cve_id" in params and params["cve_id"]:
            req_params["cveId"] = params["cve_id"].strip().upper()
        if "keyword" in params and params["keyword"]:
            req_params["keywordSearch"] = params["keyword"].strip()
        if "resultsPerPage" in params:
            req_params["resultsPerPage"] = min(int(params["resultsPerPage"]), 2000)
        else:
            req_params["resultsPerPage"] = 100
        if "startIndex" in params:
            req_params["startIndex"] = int(params["startIndex"])
        if params.get("pubStartDate"):
            req_params["pubStartDate"] = params["pubStartDate"]
        if params.get("pubEndDate"):
            req_params["pubEndDate"] = params["pubEndDate"]

        try:
            with httpx.Client(
                timeout=float(self.timeout), follow_redirects=True
            ) as client:
                response = client.get(
                    NVD_API_URL, headers=self.headers, params=req_params
                )
                if response.status_code != 200:
                    raise NetworkError(
                        endpoint="NVD",
                        status=response.status_code,
                        message=f"NVD API returned status code {response.status_code}",
                    )
                return response.text
        except httpx.HTTPError as e:
            raise NetworkError(
                endpoint="NVD", message=f"HTTP request to NVD failed: {e}"
            ) from e

    def parse(self, raw_data: str) -> list[dict[str, Any]]:
        """Parse raw NVD JSON into list of item dicts."""
        import json

        try:
            data = json.loads(raw_data)
            vulnerabilities = data.get("vulnerabilities", [])
            records = []
            for item in vulnerabilities:
                cve_obj = item.get("cve", {})
                if cve_obj:
                    records.append(cve_obj)
            return records
        except Exception as e:
            log.error(f"Failed to parse NVD JSON: {e}")
            return []

    def normalize(self, record: dict[str, Any]) -> dict[str, Any]:
        """Normalize NVD CVE JSON record into canonical schema."""
        cve_id = str(record.get("id", "")).strip().upper()
        if not cve_id.startswith("CVE-"):
            raise ValueError("NVD record missing valid CVE ID")

        # Extract descriptions
        descriptions = record.get("descriptions", [])
        summary = ""
        for d in descriptions:
            if d.get("lang") == "en":
                summary = d.get("value", "")
                break
        if not summary and descriptions:
            summary = descriptions[0].get("value", "")

        # Extract CVSS metrics (v31 preferred, fallback v30, v2)
        metrics = record.get("metrics", {})
        cvss_score = None
        severity = None
        vector = None

        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = float(cvss_data["baseScore"])
            severity = str(cvss_data.get("baseSeverity", "")).capitalize() or None
            vector = cvss_data.get("vectorString")
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = float(cvss_data["baseScore"])
            severity = str(cvss_data.get("baseSeverity", "")).capitalize() or None
            vector = cvss_data.get("vectorString")
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss_score = float(cvss_data["baseScore"])
            base_sev = metrics["cvssMetricV2"][0].get("baseSeverity", "INFO")
            severity = str(base_sev).capitalize() if base_sev else None
            vector = cvss_data.get("vectorString")

        # Dates
        published = record.get("published", "")[:10]
        updated = record.get("lastModified", "")[:10]

        # References
        references = [
            r.get("url") for r in record.get("references", []) if r.get("url")
        ]

        # Weaknesses (CWE)
        cwe_obj = None
        weaknesses = record.get("weaknesses", [])
        if weaknesses:
            for w in weaknesses:
                for desc_item in w.get("description", []):
                    cwe_str = desc_item.get("value", "")
                    if cwe_str.startswith("CWE-"):
                        try:
                            num = int(cwe_str.replace("CWE-", ""))
                            cwe_obj = {"id": num, "name": cwe_str}
                            break
                        except ValueError:
                            pass
                if cwe_obj:
                    break

        # Affected configurations / CPEs
        products = []
        configurations = record.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        p_vendor = parts[3]
                        p_product = parts[4]
                        p_version = parts[5] if len(parts) > 5 else "*"
                        products.append(
                            {"name": f"{p_vendor}/{p_product}", "version": p_version}
                        )

        vendor = products[0]["name"].split("/")[0] if products else None

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
            "references": references,
            "exploit_available": False,
            "epss": None,
            "vendor": vendor,
            "cwe": cwe_obj,
            "tags": [],
            "sources": ["NVD"],
        }

    def fetch_and_normalize(
        self, query_params: dict[str, Any] | None = None
    ) -> list[CVEModel]:
        """Fetch raw NVD feed, parse, and normalize into list of CVEModel."""
        raw = self.fetch(query_params=query_params)
        records = self.parse(raw)
        models = []
        for rec in records:
            try:
                norm_dict = self.normalize(rec)
                cwe_dict = norm_dict.pop("cwe", None)
                if cwe_dict:
                    norm_dict["cwe"] = CWEID(**cwe_dict)
                models.append(CVEModel(**norm_dict))
            except Exception as e:
                log.warning(f"Error normalizing NVD record {rec.get('id')}: {e}")
        return models
