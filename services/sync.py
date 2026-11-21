"""
Synchronization service.

Purpose: Pull CVE data from NVD, CVE.org, CISA KEV and FIRST EPSS, merge it per
CVE (``core.merge``) and persist it.
Fixes: B2 (API key from settings), B7 (KEV catalogue refreshed at most once per
TTL instead of every search; EPSS batched), B1 (merge-on-save in repository).
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Any

from config.settings import get_settings
from core.merge import merge_models
from core.models import CVEModel
from sources.cve_org import CVEOrgAdapter
from sources.epss import EPSSAdapter
from sources.nvd import NVDAdapter
from sources.vendor import CISAKEVAdapter
from storage.repositories import CVERepository
from storage.system_repositories import SourceStateRepository
from utils.logger import get_logger

log = get_logger(__name__)
NVD_WINDOW_DAYS = 120
ALL_SOURCES = ("nvd", "cve_org", "cisa_kev", "epss")


class SyncService:
    def __init__(self, repo: CVERepository | None = None) -> None:
        settings = get_settings()
        self.settings = settings
        self.repo = repo or CVERepository()
        self.state = SourceStateRepository()
        self.nvd_adapter = NVDAdapter(api_key=settings.nvd_api_key)
        self.cve_org_adapter = CVEOrgAdapter(api_key=settings.cve_org_api_key)
        self.cisa_kev_adapter = CISAKEVAdapter()
        self.epss_adapter = EPSSAdapter()

    @staticmethod
    def _selected(sources: list[str] | None) -> set[str]:
        selected = {item.lower().strip() for item in (sources or ["nvd", "cisa_kev"])}
        aliases = {"kev": "cisa_kev", "cve.org": "cve_org", "first_epss": "epss"}
        selected = {aliases.get(item, item) for item in selected}
        if "all" in selected:
            selected |= set(ALL_SOURCES)
        return selected

    def sync_sources(
        self,
        sources: list[str] | None = None,
        query: str = "",
        limit: int = 100,
        date_range: tuple[str, str] | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        selected = self._selected(sources)
        models: list[CVEModel] = []
        counts: dict[str, int] = {}
        errors: dict[str, str] = {}
        started = time.monotonic()
        is_cve_query = query.strip().upper().startswith("CVE-")

        if "cisa_kev" in selected:
            if force or self.state.is_stale("cisa_kev", self.settings.kev_ttl_hours):
                self.state.mark_attempt("cisa_kev")
                try:
                    batch = self.cisa_kev_adapter.fetch_and_normalize()
                    models.extend(batch)
                    counts["cisa_kev"] = len(batch)
                    self.state.mark_success("cisa_kev", row_count=len(batch))
                except Exception as error:
                    log.error(f"CISA KEV sync failed: {error}")
                    counts["cisa_kev"] = 0
                    errors["cisa_kev"] = str(error)
                    self.state.mark_failure("cisa_kev", str(error))
            else:
                counts["cisa_kev"] = 0  # cached catalogue is still fresh

        primary: list[CVEModel] = []
        if "nvd" in selected:
            self.state.mark_attempt("nvd")
            try:
                params: dict[str, Any] = {"resultsPerPage": limit}
                if query:
                    if is_cve_query:
                        params["cve_id"] = query.strip()
                    else:
                        params["keyword"] = query
                if date_range and not params.get("cve_id"):
                    params["pubStartDate"], params["pubEndDate"] = date_range
                batch = self._fetch_nvd(params, limit)
                primary.extend(batch)
                counts["nvd"] = len(batch)
                self.state.mark_success("nvd")
            except Exception as error:
                log.error(f"NVD sync failed: {error}")
                counts["nvd"] = 0
                errors["nvd"] = str(error)
                self.state.mark_failure("nvd", str(error))

        if "cve_org" in selected and is_cve_query:
            try:
                batch = self.cve_org_adapter.fetch_and_normalize(
                    query_params={"cve_id": query.strip()}
                )
                primary.extend(batch)
                counts["cve_org"] = len(batch)
            except Exception as error:
                log.error(f"CVE.org sync failed: {error}")
                counts["cve_org"] = 0
                errors["cve_org"] = str(error)

        models.extend(primary)
        ids = sorted({model.id for model in primary if model.id})
        if ids and "epss" in selected:
            batch = self.epss_adapter.fetch_and_normalize(
                query_params={"cves": ids}, batch_size=self.settings.epss_batch_size
            )
            models.extend(batch)
            counts["epss"] = len(batch)

        merged: dict[str, CVEModel] = {}
        for model in models:
            current = merged.get(model.id)
            merged[model.id] = (
                model if current is None else merge_models(current, model)
            )

        unique = list(merged.values())
        stored = self.repo.save_bulk(unique) if unique else 0
        self._metric("sync.duration_ms", (time.monotonic() - started) * 1000)
        for source in errors:
            self._metric("integration.failure", 1, source=source)
        return {
            "total_synced": stored,
            "unique_records": len(unique),
            "sources": counts,
            "errors": errors,
        }

    def enrich_epss(self, cve_ids: list[str]) -> int:
        """Refresh EPSS scores for already-stored CVEs (cve_enrichment job)."""
        batch = self.epss_adapter.fetch_and_normalize(
            query_params={"cves": cve_ids}, batch_size=self.settings.epss_batch_size
        )
        return self.repo.save_bulk(batch)

    def _metric(self, name: str, value: float, **tags: Any) -> None:
        try:
            from services.metrics import record_metric

            record_metric(name, value, **tags)
        except Exception:  # metrics must never break a sync
            pass

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
                "resultsPerPage": limit - len(models),
                "pubStartDate": cursor.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "pubEndDate": window_end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            }
            models.extend(
                self.nvd_adapter.fetch_and_normalize(query_params=batch_params)
            )
            cursor = window_end
        return models[:limit]

    def _merge_models(self, current: CVEModel, incoming: CVEModel) -> CVEModel:
        """Backward-compatible wrapper around ``core.merge.merge_models``."""
        return merge_models(current, incoming)
