"""
Audit service.

Append-only, local record of security-relevant actions (template exports,
dork opens, research attestations, purges). Records *what kind* of action
happened and identifiers (CVE/EDB IDs, template ids, risk levels) — never
usernames, target domains or query text.
"""

from __future__ import annotations

from typing import Any

from storage.system_repositories import AuditRepository

ALLOWED_DETAIL_KEYS = {
    "module_type",
    "formats",
    "category",
    "risk_level",
    "count",
    "source",
    "feature",
    "outcome",
    "project_id",
}


class AuditService:
    def __init__(self, repo: AuditRepository | None = None) -> None:
        self.repo = repo or AuditRepository()

    def record(
        self,
        event: str,
        object_kind: str = "",
        object_id: str | int = "",
        risk_level: str = "",
        **details: Any,
    ) -> int:
        safe = {k: v for k, v in details.items() if k in ALLOWED_DETAIL_KEYS}
        return self.repo.record(
            event=event,
            object_kind=object_kind,
            object_id=str(object_id),
            risk_level=risk_level,
            details=safe,
        )

    def recent(self, limit: int = 50, event: str | None = None) -> list[dict[str, Any]]:
        return self.repo.list(limit=limit, event=event)

    def purge_older_than(self, days: int) -> int:
        return self.repo.purge_older_than(days)


def audit(event: str, **kwargs: Any) -> None:
    """Best-effort audit helper (never raises)."""
    try:
        AuditService().record(event, **kwargs)
    except Exception:
        pass
