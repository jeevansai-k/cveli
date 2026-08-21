from datetime import datetime, timedelta
from typing import Any

from core.models import CVEModel
from sources.cve_org import CVEOrgAdapter
from sources.epss import EPSSAdapter
from sources.nvd import NVDAdapter
from sources.vendor import CISAKEVAdapter
from storage.repositories import CVERepository
from utils.logger import get_logger

log = get_logger(__name__)
NVD_WINDOW_DAYS = 120


class SyncService:
    def __init__(self, repo: CVERepository | None = None) -> None:
        self.repo = repo or CVERepository()
        self.nvd_adapter = NVDAdapter()
        self.cve_org_adapter = CVEOrgAdapter()
        self.cisa_kev_adapter = CISAKEVAdapter()
        self.epss_adapter = EPSSAdapter()

    def sync_sources(
        self,
        sources: list[str] | None = None,
        query: str = "",
        limit: int = 100,
        date_range: tuple[str, str] | None = None,
    ) -> dict[str, Any]:
        selected = [
            item.lower().strip() for item in (sources or ["nvd", "cisa_kev", "epss"])
        ]
        models: list[CVEModel] = []
        counts: dict[str, int] = {}

        if {"cisa_kev", "kev", "all"} & set(selected):
            try:
                batch = self.cisa_kev_adapter.fetch_and_normalize()
                models.extend(batch)
                counts["cisa_kev"] = len(batch)
            except Exception as error:
                log.error(f"CISA KEV sync failed: {error}")
                counts["cisa_kev"] = 0

        if "nvd" in selected or "all" in selected:
            try:
                params: dict[str, Any] = {"resultsPerPage": limit}
                if query:
                    if query.upper().startswith("CVE-"):
                        params["cve_id"] = query
                    else:
                        params["keyword"] = query
                if date_range and not params.get("cve_id"):
                    params["pubStartDate"], params["pubEndDate"] = date_range
                batch = self._fetch_nvd(params, limit)
                models.extend(batch)
                counts["nvd"] = len(batch)
            except Exception as error:
                log.error(f"NVD sync failed: {error}")
                counts["nvd"] = 0

        if {"cve_org", "cve.org", "all"} & set(selected) and query.upper().startswith(
            "CVE-"
        ):
            try:
                batch = self.cve_org_adapter.fetch_and_normalize(
                    query_params={"cve_id": query}
                )
                models.extend(batch)
                counts["cve_org"] = len(batch)
            except Exception as error:
                log.error(f"CVE.org sync failed: {error}")
                counts["cve_org"] = 0

        ids = sorted({model.id for model in models if model.id})
        if ids and (
            "epss" in selected or "first_epss" in selected or "all" in selected
        ):
            try:
                batch = self.epss_adapter.fetch_and_normalize(
                    query_params={"cves": ids}
                )
                models.extend(batch)
                counts["epss"] = len(batch)
            except Exception as error:
                log.error(f"FIRST EPSS sync failed: {error}")
                counts["epss"] = 0

        merged: dict[str, CVEModel] = {}
        for model in models:
            current = merged.get(model.id)
            if current is None:
                merged[model.id] = model
                continue
            merged[model.id] = self._merge_models(current, model)

        unique = list(merged.values())
        stored = self.repo.save_bulk(unique) if unique else 0
        return {
            "total_synced": stored,
            "unique_records": len(unique),
            "sources": counts,
        }

    def _fetch_nvd(self, params: dict[str, Any], limit: int) -> list[CVEModel]:
        if not params.get("pubStartDate") or not params.get("pubEndDate"):
            return self.nvd_adapter.fetch_and_normalize(query_params=params)

        start = datetime.fromisoformat(params["pubStartDate"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(params["pubEndDate"].replace("Z", "+00:00"))
        models: list[CVEModel] = []
        cursor = start
        while cursor < end and len(models) < limit:
            window_end = min(cursor + timedelta(days=NVD_WINDOW_DAYS), end)
            batch_params = {
                **params,
                "resultsPerPage": min(2000, limit - len(models)),
                "pubStartDate": cursor.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "pubEndDate": window_end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            }
            batch = self.nvd_adapter.fetch_and_normalize(query_params=batch_params)
            models.extend(batch)
            cursor = window_end
        return models[:limit]

    def _merge_models(self, current: CVEModel, incoming: CVEModel) -> CVEModel:
        if incoming.exploit_available:
            current.exploit_available = True
        if incoming.epss is not None:
            current.epss = incoming.epss
        if incoming.epss_percentile is not None:
            current.epss_percentile = incoming.epss_percentile
        if incoming.cvss is not None and (
            current.cvss is None or incoming.cvss > current.cvss
        ):
            current.cvss = incoming.cvss
            current.severity = incoming.severity
        if incoming.vector and not current.vector:
            current.vector = incoming.vector
        if incoming.summary and len(incoming.summary) > len(current.summary):
            current.summary = incoming.summary
        if incoming.published and not current.published:
            current.published = incoming.published
        if incoming.updated and (
            not current.updated or incoming.updated > current.updated
        ):
            current.updated = incoming.updated
        if incoming.kev_date and not current.kev_date:
            current.kev_date = incoming.kev_date
        if incoming.vendor and not current.vendor:
            current.vendor = incoming.vendor
        if incoming.cwe and not current.cwe:
            current.cwe = incoming.cwe
        if len(incoming.affected_products) > len(current.affected_products):
            current.affected_products = incoming.affected_products
        current.references = list(
            dict.fromkeys([*current.references, *incoming.references])
        )
        current.tags = list(dict.fromkeys([*current.tags, *incoming.tags]))
        current.sources = list(dict.fromkeys([*current.sources, *incoming.sources]))
        return current
