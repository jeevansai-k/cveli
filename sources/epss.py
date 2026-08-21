import json
from typing import Any

import httpx

from core.models import CVEModel
from sources.base import BaseAdapter
from utils.errors import NetworkError
from utils.logger import get_logger

log = get_logger(__name__)

FIRST_EPSS_API_URL = "https://api.first.org/data/v1/epss"


class EPSSAdapter(BaseAdapter):
    name = "epss"

    def __init__(self, api_key: str | None = None, timeout: int = 30):
        super().__init__(api_key=api_key, timeout=timeout)
        self.headers = {"User-Agent": "cveli/0.1.0"}

    def fetch(self, query_params: dict[str, Any] | None = None) -> str:
        cves = (query_params or {}).get("cves") or (query_params or {}).get("cve_id")
        if isinstance(cves, list):
            cves = ",".join(cve.strip().upper() for cve in cves if cve)
        if not cves:
            raise NetworkError(
                endpoint="FIRST EPSS", message="cve_id parameter required"
            )

        try:
            with httpx.Client(
                timeout=float(self.timeout), follow_redirects=True
            ) as client:
                response = client.get(
                    FIRST_EPSS_API_URL, headers=self.headers, params={"cve": cves}
                )
                if response.status_code != 200:
                    raise NetworkError(
                        endpoint="FIRST EPSS",
                        status=response.status_code,
                        message=(
                            f"FIRST EPSS API returned status {response.status_code}"
                        ),
                    )
                return response.text
        except httpx.HTTPError as error:
            raise NetworkError(
                endpoint="FIRST EPSS",
                message=f"HTTP request to FIRST EPSS failed: {error}",
            ) from error

    def parse(self, raw_data: str) -> list[dict[str, Any]]:
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError as error:
            log.error(f"Failed to parse FIRST EPSS JSON: {error}")
            return []
        records = data.get("data", [])
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
        self, query_params: dict[str, Any] | None = None
    ) -> list[CVEModel]:
        try:
            raw = self.fetch(query_params=query_params)
            return [CVEModel(**self.normalize(record)) for record in self.parse(raw)]
        except Exception as error:
            log.warning(f"FIRST EPSS fetch failed: {error}")
            return []
