from typing import Any

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
        normalized_type = target_type.strip().lower()
        if normalized_type not in self.VALID_TARGET_TYPES:
            raise ValidationError(
                field="target_type",
                value=target_type,
                message="Target type must be vendor, product, or cwe",
            )
        normalized_value = target_value.strip()
        if not normalized_value:
            raise ValidationError(
                field="target_value",
                value=target_value,
                message="Target value cannot be empty",
            )
        return self.w_repo.add(
            target_type=normalized_type, target_value=normalized_value, notes=notes
        )

    def list_targets(self) -> list[dict[str, Any]]:
        return self.w_repo.list_all()

    def remove_target(self, item_id: str) -> bool:
        return self.w_repo.remove(item_id)

    def check_alerts(self, limit_per_target: int = 5) -> dict[str, Any]:
        targets = self.list_targets()
        alerts: list[dict[str, Any]] = []
        for target in targets:
            target_type = target["target_type"]
            target_value = target["target_value"]
            if target_type == "vendor":
                matches = self.cve_repo.search(
                    vendor=target_value, limit=limit_per_target
                )
            elif target_type == "cwe":
                matches = self.cve_repo.search(
                    cwe_id=target_value, limit=limit_per_target
                )
            else:
                matches = self.cve_repo.search(
                    query=target_value, limit=limit_per_target
                )
            if matches:
                alerts.append(
                    {
                        "watchlist_item": target,
                        "match_count": len(matches),
                        "cves": [match.to_dict() for match in matches],
                    }
                )
        return {
            "watchlist_count": len(targets),
            "alert_count": len(alerts),
            "alerts": alerts,
        }
