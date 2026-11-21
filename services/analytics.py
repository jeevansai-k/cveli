"""Analytics service: database statistics and data-source freshness."""

from __future__ import annotations

from typing import Any

from storage.repositories import CVERepository


class AnalyticsService:
    def __init__(self, repo: CVERepository | None = None) -> None:
        self.repo = repo or CVERepository()

    def get_summary_stats(self) -> dict[str, int]:
        stats = dict(self.repo.get_stats())
        try:
            from storage.exploit_repository import ExploitRepository

            stats["exploitdb_entries"] = ExploitRepository().count()
        except Exception:
            stats["exploitdb_entries"] = 0
        return stats

    def source_status(self) -> list[dict[str, Any]]:
        from storage.system_repositories import SourceStateRepository

        rows = SourceStateRepository().all()
        for row in rows:
            for key in ("last_success", "last_attempt"):
                if row[key] is not None:
                    row[key] = row[key].strftime("%Y-%m-%d %H:%M UTC")
        return rows
