"""
NVD API 2.0 Source Adapter.

Purpose: Fetch and normalize vulnerability records from NVD.
Fix B6: follows ``startIndex`` pagination up to ``totalResults`` (bounded by the
caller's limit) and goes through the shared rate-limited HTTP client
(5 req/30 s anonymous, 50 req/30 s with ``NVD_API_KEY``).
"""

from __future__ import annotations

import json
from typing import Any

from config.settings import get_settings
from core.models import CWEID, CVEModel
from core.text import sanitize_terminal_text
from sources.base import BaseAdapter
from utils.http import configure_host_limit
from utils.logger import get_logger

log = get_logger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_HOST = "services.nvd.nist.gov"
NVD_MAX_PAGE = 2000
VALID_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


class NVDAdapter(BaseAdapter):
    """Adapter for National Vulnerability Database (NVD) API 2.0."""

    name = "nvd"
    endpoint = "NVD"

    def __init__(self, api_key: str | None = None, timeout: float | None = None):
        settings = get_settings()
        super().__init__(api_key=api_key or settings.nvd_api_key, timeout=timeout)
        self.headers: dict[str, str] = {}
        if self.api_key:
            self.headers["apiKey"] = self.api_key
        rate, per = (50, 30.0) if self.api_key else (5, 30.0)
        configure_host_limit(NVD_HOST, rate, per)

    def build_params(self, params: dict[str, Any]) -> dict[str, Any]:
        req: dict[str, Any] = {}
        if params.get("cve_id"):
            req["cveId"] = str(params["cve_id"]).strip().upper()
        if params.get("keyword"):
            req["keywordSearch"] = str(params["keyword"]).strip()
        req["resultsPerPage"] = min(
            int(params.get("resultsPerPage", 100) or 100), NVD_MAX_PAGE
        )
        if params.get("startIndex"):
            req["startIndex"] = int(params["startIndex"])
        for key in ("pubStartDate", "pubEndDate", "lastModStartDate", "lastModEndDate"):
            if params.get(key):
                req[key] = params[key]
        return req

    def fetch(self, query_params: dict[str, Any] | None = None) -> str:
        """Fetch one raw JSON page from NVD API 2.0."""
        response = self.http.get(
            NVD_API_URL,
            params=self.build_params(query_params or {}),
            headers=self.headers,
        )
        return response.text

    def parse(self, raw_data: str | bytes) -> list[dict[str, Any]]:
        """Parse raw NVD JSON into list of item dicts."""
        try:
            data = json.loads(raw_data)
        except (TypeError, ValueError) as error:
            log.error(f"Failed to parse NVD JSON: {error}")
            return []
        if not isinstance(data, dict):
            return []
        return [
            item["cve"]
            for item in data.get("vulnerabilities", []) or []
            if isinstance(item, dict) and isinstance(item.get("cve"), dict)
        ]

    @staticmethod
    def total_results(raw_data: str | bytes) -> int:
        try:
            return int(json.loads(raw_data).get("totalResults", 0))
        except (TypeError, ValueError, AttributeError):
            return 0

    def _cvss(
        self, metrics: dict[str, Any]
    ) -> tuple[float | None, str | None, str | None]:
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
            entries = metrics.get(key) or []
            if entries:
                primary = next(
                    (e for e in entries if e.get("type") == "Primary"), entries[0]
                )
                data = primary.get("cvssData", {})
                if data.get("baseScore") is None:
                    continue
                severity = str(data.get("baseSeverity", "")).capitalize() or None
                return float(data["baseScore"]), severity, data.get("vectorString")
        entries = metrics.get("cvssMetricV2") or []
        if entries:
            data = entries[0].get("cvssData", {})
            if data.get("baseScore") is not None:
                base_sev = entries[0].get("baseSeverity")
                severity = str(base_sev).capitalize() if base_sev else None
                return float(data["baseScore"]), severity, data.get("vectorString")
        return None, None, None

    def normalize(self, record: dict[str, Any]) -> dict[str, Any]:
        """Normalize NVD CVE JSON record into canonical schema."""
        cve_id = str(record.get("id", "")).strip().upper()
        if not cve_id.startswith("CVE-"):
            raise ValueError("NVD record missing valid CVE ID")

        descriptions = record.get("descriptions", []) or []
        summary = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"), ""
        )
        if not summary and descriptions:
            summary = descriptions[0].get("value", "")

        cvss_score, severity, vector = self._cvss(record.get("metrics", {}) or {})

        references: list[str] = []
        details: list[dict[str, Any]] = []
        for ref in record.get("references", []) or []:
            url = ref.get("url") if isinstance(ref, dict) else None
            if not url or url in references:
                continue
            references.append(url)
            details.append(
                {
                    "url": url,
                    "source": str(ref.get("source", "")),
                    "tags": [str(tag) for tag in ref.get("tags", []) or []],
                }
            )

        cwe_obj = None
        for weakness in record.get("weaknesses", []) or []:
            for desc_item in weakness.get("description", []) or []:
                cwe_str = str(desc_item.get("value", ""))
                if cwe_str.startswith("CWE-"):
                    try:
                        cwe_obj = {"id": int(cwe_str[4:]), "name": cwe_str}
                    except ValueError:
                        continue
                    break
            if cwe_obj:
                break

        products: list[dict[str, str]] = []
        for config in record.get("configurations", []) or []:
            for node in config.get("nodes", []) or []:
                for cpe_match in node.get("cpeMatch", []) or []:
                    if cpe_match.get("vulnerable") is False:
                        continue
                    parts = str(cpe_match.get("criteria", "")).split(":")
                    if len(parts) >= 5:
                        version = parts[5] if len(parts) > 5 else "*"
                        for bound in (
                            "versionStartIncluding",
                            "versionEndExcluding",
                            "versionEndIncluding",
                        ):
                            if cpe_match.get(bound):
                                version = (
                                    f"{bound.replace('version', '')} {cpe_match[bound]}"
                                )
                        product = {"name": f"{parts[3]}/{parts[4]}", "version": version}
                        if product not in products:
                            products.append(product)

        vendor = products[0]["name"].split("/")[0] if products else None

        return {
            "id": cve_id,
            "summary": sanitize_terminal_text(summary),
            "severity": severity if severity in VALID_SEVERITIES else None,
            "cvss": cvss_score,
            "vector": vector,
            "published": str(record.get("published", ""))[:10],
            "updated": str(record.get("lastModified", ""))[:10],
            "affected_products": products,
            "references": references,
            "reference_details": details,
            "exploit_available": False,
            "epss": None,
            "vendor": vendor,
            "cwe": cwe_obj,
            "tags": [],
            "sources": ["NVD"],
        }

    def _to_models(self, records: list[dict[str, Any]]) -> list[CVEModel]:
        models = []
        for rec in records:
            try:
                norm = self.normalize(rec)
                cwe_dict = norm.pop("cwe", None)
                if cwe_dict:
                    norm["cwe"] = CWEID(**cwe_dict)
                models.append(CVEModel(**norm))
            except Exception as error:
                log.warning(f"Error normalizing NVD record {rec.get('id')}: {error}")
        return models

    def fetch_and_normalize(
        self, query_params: dict[str, Any] | None = None
    ) -> list[CVEModel]:
        """Fetch every page (bounded by ``resultsPerPage`` as the overall limit)."""
        params = dict(query_params or {})
        limit = max(1, int(params.get("resultsPerPage", 100) or 100))
        start = int(params.get("startIndex", 0) or 0)
        models: list[CVEModel] = []
        while True:
            page_size = min(NVD_MAX_PAGE, limit - len(models))
            raw = self.fetch(
                {**params, "resultsPerPage": page_size, "startIndex": start}
            )
            records = self.parse(raw)
            models.extend(self._to_models(records))
            total = self.total_results(raw)
            start += len(records)
            if not records or start >= total or len(models) >= limit:
                break
        return models[:limit]
