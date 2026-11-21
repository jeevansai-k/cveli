"""
FIRST EPSS Source Adapter.

Purpose: Exploit Prediction Scoring System probabilities for known CVE IDs.
Fix B7: requests are batched (≤100 IDs) so long ID lists never exceed URL limits.
"""

from __future__ import annotations

import json
import re
from typing import Any

from core.models import CVEModel
from sources.base import BaseAdapter
from utils.errors import NetworkError
from utils.logger import get_logger

log = get_logger(__name__)

FIRST_EPSS_API_URL = "https://api.first.org/data/v1/epss"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
MAX_BATCH = 100


def chunked(items: list[str], size: int) -> list[list[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


class EPSSAdapter(BaseAdapter):
    name = "epss"
    endpoint = "FIRST EPSS"

    def _ids(self, query_params: dict[str, Any] | None) -> list[str]:
        params = query_params or {}
        raw = params.get("cves") or params.get("cve_id") or []
        if isinstance(raw, str):
            raw = raw.split(",")
        ids = [str(cve).strip().upper() for cve in raw if cve]
        return list(dict.fromkeys(cve for cve in ids if CVE_RE.match(cve)))

    def fetch(self, query_params: dict[str, Any] | None = None) -> str:
        ids = self._ids(query_params)
        if not ids:
            raise NetworkError(
                endpoint="FIRST EPSS", message="cve_id parameter required"
            )
        if len(ids) > MAX_BATCH:
            raise NetworkError(
                endpoint="FIRST EPSS",
                message=f"at most {MAX_BATCH} CVE IDs per request",
            )
        response = self.http.get(
            FIRST_EPSS_API_URL, params={"cve": ",".join(ids), "limit": len(ids)}
        )
        return response.text

    def parse(self, raw_data: str | bytes) -> list[dict[str, Any]]:
        try:
            data = json.loads(raw_data)
        except (TypeError, ValueError) as error:
            log.error(f"Failed to parse FIRST EPSS JSON: {error}")
            return []
        records = data.get("data", []) if isinstance(data, dict) else []
        return records if isinstance(records, list) else []

    def normalize(self, record: dict[str, Any]) -> dict[str, Any]:
        cve_id = str(record.get("cve", "")).strip().upper()
        if not cve_id.startswith("CVE-"):
            raise ValueError("FIRST EPSS record missing valid CVE ID")
        return {
            "id": cve_id,
            "summary": "",
            "severity": None,
            "cvss": None,
            "epss": float(record["epss"]),
            "epss_percentile": float(record["percentile"])
            if record.get("percentile") is not None
            else None,
            "tags": [],
            "sources": ["FIRST EPSS"],
        }

    def fetch_and_normalize(
        self, query_params: dict[str, Any] | None = None, batch_size: int = MAX_BATCH
    ) -> list[CVEModel]:
        models: list[CVEModel] = []
        for batch in chunked(
            self._ids(query_params), max(1, min(batch_size, MAX_BATCH))
        ):
            try:
                raw = self.fetch({"cves": batch})
            except Exception as error:
                log.warning(f"FIRST EPSS batch failed: {error}")
                continue
            for record in self.parse(raw):
                try:
                    models.append(CVEModel(**self.normalize(record)))
                except Exception as error:
                    log.warning(f"Skipping malformed EPSS record: {error}")
        return models
