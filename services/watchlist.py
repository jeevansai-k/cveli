"""
Watchlist service.

Tracks vendors, products and CWEs. ``check_alerts`` reports every stored match
and which matches are *new since the previous check* (B15), then records the
check time per target.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from core.text import has_control_chars
from core.validator import validate_cwe_id
from storage.database import utcnow
from storage.repositories import CVERepository, WatchlistRepository
from utils.errors import ValidationError


class WatchlistService:
    VALID_TARGET_TYPES = {"vendor", "product", "cwe"}

    def __init__(
        self,
        watchlist_repo: WatchlistRepository | None = None,
        cve_repo: CVERepository | None = None,
    ) -> None:
        self.w_repo = watchlist_repo or WatchlistRepository()
        self.cve_repo = cve_repo or CVERepository()

    def add_target(
        self, target_type: str, target_value: str, notes: str = ""
    ) -> dict[str, Any]:
        normalized_type = (target_type or "").strip().lower()
        if normalized_type not in self.VALID_TARGET_TYPES:
            raise ValidationError(
                field="target_type",
                value=target_type,
                message="Target type must be vendor, product, or cwe",
            )
        normalized_value = (target_value or "").strip()
        if not normalized_value or len(normalized_value) > 128:
            raise ValidationError(
                field="target_value",
                value=target_value,
                message="Target value must be 1-128 characters",
            )
        if has_control_chars(normalized_value) or has_control_chars(notes or ""):
            raise ValidationError(
                field="target_value",
                value=target_value,
                message="Control characters are not allowed",
            )
        if normalized_type == "cwe":
            normalized_value = normalized_value.upper()
            if normalized_value.isdigit():
                normalized_value = f"CWE-{normalized_value}"
            validate_cwe_id(normalized_value)
        return self.w_repo.add(
            target_type=normalized_type, target_value=normalized_value, notes=notes
        )

    def list_targets(self) -> list[dict[str, Any]]:
        return self.w_repo.list_all()

    def remove_target(self, item_id: str) -> bool:
        return self.w_repo.remove(item_id)

    def _matches(self, target: dict[str, Any], limit: int, **extra: Any):
        target_type = target["target_type"]
        value = target["target_value"]
        if target_type == "vendor":
            return self.cve_repo.search(vendor=value, limit=limit, **extra)
        if target_type == "cwe":
            return self.cve_repo.search(cwe_id=value, limit=limit, **extra)
        return self.cve_repo.search(query=value, limit=limit, **extra)

    def check_alerts(
        self, limit_per_target: int = 5, mark_checked: bool = True
    ) -> dict[str, Any]:
        targets = self.list_targets()
        alerts: list[dict[str, Any]] = []
        now = utcnow()
        for target in targets:
            matches = self._matches(target, limit_per_target)
            last = target.get("last_checked_at") or ""
            new_matches = []
            if last:
                since = datetime.fromisoformat(last)
                new_matches = self._matches(
                    target, limit_per_target, first_seen_after=since
                )
            else:
                new_matches = matches
            if matches:
                alerts.append(
                    {
                        "watchlist_item": target,
                        "match_count": len(matches),
                        "new_count": len(new_matches),
                        "cves": [match.to_dict() for match in matches],
                        "new_cve_ids": [match.id for match in new_matches],
                    }
                )
            if mark_checked:
                self.w_repo.mark_checked(target["id"], now)
        return {
            "watchlist_count": len(targets),
            "alert_count": len(alerts),
            "new_total": sum(alert["new_count"] for alert in alerts),
            "alerts": alerts,
        }
