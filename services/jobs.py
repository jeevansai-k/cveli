"""
Background jobs.

CVELI has no daemon. Jobs run (a) lazily when data is stale, (b) in Textual
worker threads from the TUI, or (c) explicitly via ``cveli jobs run <name>`` —
suitable for cron or a systemd timer (see docs/operations.md).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from config.settings import get_settings
from utils.logger import get_logger

log = get_logger(__name__)


def exploitdb_refresh(force: bool = False) -> dict[str, Any]:
    from services.exploitdb import ExploitDBService

    return ExploitDBService().refresh(force=force).model_dump()


def cve_enrichment(force: bool = False, limit: int = 1000) -> dict[str, Any]:
    """Refresh the CISA KEV catalogue and EPSS scores for stored CVEs."""
    from services.sync import SyncService
    from storage.repositories import CVERepository

    sync = SyncService()
    kev = sync.sync_sources(sources=["cisa_kev"], force=force)
    ids = CVERepository().all_ids(limit=limit)
    epss = sync.enrich_epss(ids) if ids else 0
    return {
        "kev_records": kev["sources"].get("cisa_kev", 0),
        "epss_updated": epss,
        "errors": kev.get("errors", {}),
    }


def cache_cleanup(force: bool = False) -> dict[str, Any]:
    from storage.cache import cache_cleanup as cleanup
    from storage.system_repositories import AuditRepository, MetricsRepository

    settings = get_settings()
    result: dict[str, Any] = dict(cleanup())
    result["metrics_purged"] = MetricsRepository().purge_older_than(
        settings.metrics_retention_days
    )
    result["audit_purged"] = AuditRepository().purge_older_than(
        settings.audit_retention_days
    )
    return result


def index_rebuild(force: bool = False) -> dict[str, Any]:
    from services.exploitdb import ExploitDBService

    return ExploitDBService().rebuild_index()


JOBS: dict[str, Callable[..., dict[str, Any]]] = {
    "exploitdb_refresh": exploitdb_refresh,
    "cve_enrichment": cve_enrichment,
    "cache_cleanup": cache_cleanup,
    "index_rebuild": index_rebuild,
}


def run_job(name: str, force: bool = False) -> dict[str, Any]:
    if name not in JOBS:
        raise KeyError(f"Unknown job '{name}'. Available: {', '.join(JOBS)}")
    log.info(f"Running job {name} (force={force})")
    result = JOBS[name](force=force)
    try:
        from services.metrics import record_metric

        record_metric("job.run", 1, feature=name)
    except Exception:
        pass
    return result


def run_due_jobs() -> dict[str, Any]:
    """Run jobs whose data is stale (used on startup / by the scheduler)."""
    from storage.system_repositories import SourceStateRepository

    settings = get_settings()
    state = SourceStateRepository()
    results: dict[str, Any] = {}
    if settings.feature_exploitdb and state.is_stale(
        "exploitdb", settings.exploitdb_ttl_hours
    ):
        try:
            results["exploitdb_refresh"] = exploitdb_refresh()
        except Exception as error:
            results["exploitdb_refresh"] = {"error": str(error)}
    if state.is_stale("cisa_kev", settings.kev_ttl_hours):
        try:
            results["cve_enrichment"] = cve_enrichment()
        except Exception as error:
            results["cve_enrichment"] = {"error": str(error)}
    results["cache_cleanup"] = cache_cleanup()
    return results
