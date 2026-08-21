"""
Filter Criteria Handling.

Purpose: Define and apply filter criteria to search results.
Inputs: Filter dictionary with various criteria types.
Outputs: Filtered result sets based on applied filters.
Responsibilities: Handle severity ranges, CVSS scoring, date filtering.
Dependencies: utils.errors.ValidationError, datetime
"""

from datetime import datetime
from typing import Any

from utils.errors import ValidationError


class BaseFilter:
    """Base class for all filter types."""

    def __init__(self, name: str):
        self.name = name

    def apply(self, record: dict | Any) -> bool:
        """Apply this filter to a single record. Returns True if included."""
        raise NotImplementedError


class SeverityFilter(BaseFilter):
    """Filter CVEs by severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)."""

    SEVERITY_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def __init__(
        self, level: str | None = None, exclude_severities: list[str] | None = None
    ):
        super().__init__("severity_filter")
        self.level = level.upper().strip() if level else None
        self.exclude_severities = [
            s.upper().strip() for s in (exclude_severities or [])
        ]

    def apply(self, record: dict | Any) -> bool:
        rec_dict = (
            record
            if isinstance(record, dict)
            else (record.to_dict() if hasattr(record, "to_dict") else record.__dict__)
        )
        severity = str(rec_dict.get("severity") or "").upper().strip()

        if self.level and severity != self.level:
            return False

        if self.exclude_severities and severity in self.exclude_severities:
            return False

        return True


class CVSSRangeFilter(BaseFilter):
    """Filter CVEs by CVSS score range."""

    def __init__(self, min_score: float = 0.0, max_score: float | None = None):
        super().__init__("cvss_range_filter")
        self.min_score = float(min_score)
        self.max_score = float(max_score) if max_score is not None else None

    def apply(self, record: dict | Any) -> bool:
        rec_dict = (
            record
            if isinstance(record, dict)
            else (record.to_dict() if hasattr(record, "to_dict") else record.__dict__)
        )
        cvss_val = (
            rec_dict.get("cvss")
            if "cvss" in rec_dict
            else rec_dict.get("cvss_score", 0.0)
        )

        try:
            score = float(cvss_val or 0.0)
        except (ValueError, TypeError):
            return False

        if score < self.min_score:
            return False

        if self.max_score is not None and score > self.max_score:
            return False

        return True


class DateFilter(BaseFilter):
    """Filter CVEs by publish/update date range."""

    def __init__(
        self,
        published_since: str | None = None,
        published_before: str | None = None,
        updated_since: str | None = None,
        updated_before: str | None = None,
    ):
        super().__init__("date_filter")
        self.published_since = published_since
        self.published_before = published_before
        self.updated_since = updated_since
        self.updated_before = updated_before

    def _parse(self, date_str: str | None) -> datetime | None:
        if not date_str:
            return None
        from utils.time import parse_date

        return parse_date(str(date_str))

    def apply(self, record: dict | Any) -> bool:
        rec_dict = (
            record
            if isinstance(record, dict)
            else (record.to_dict() if hasattr(record, "to_dict") else record.__dict__)
        )

        pub_dt = self._parse(rec_dict.get("published"))
        pub_since_dt = self._parse(self.published_since)
        pub_before_dt = self._parse(self.published_before)

        if pub_since_dt and pub_dt and pub_dt < pub_since_dt:
            return False
        if pub_before_dt and pub_dt and pub_dt > pub_before_dt:
            return False

        upd_dt = self._parse(rec_dict.get("updated"))
        upd_since_dt = self._parse(self.updated_since)
        upd_before_dt = self._parse(self.updated_before)

        if upd_since_dt and upd_dt and upd_dt < upd_since_dt:
            return False
        if upd_before_dt and upd_dt and upd_dt > upd_before_dt:
            return False

        return True


def apply_filters(
    results: list[Any], filters: dict[str, Any] | None = None
) -> list[Any]:
    """Apply active filter criteria to result set."""
    if not results or not filters:
        return results or []

    active_filters: list[BaseFilter] = []

    if "severity" in filters and filters["severity"]:
        sev = filters["severity"]
        if isinstance(sev, str):
            active_filters.append(SeverityFilter(level=sev))
        elif isinstance(sev, dict):
            active_filters.append(SeverityFilter(**sev))

    if "cvss_range" in filters and filters["cvss_range"]:
        cvss = filters["cvss_range"]
        if isinstance(cvss, (int, float)):
            active_filters.append(CVSSRangeFilter(min_score=float(cvss)))
        elif isinstance(cvss, dict):
            active_filters.append(CVSSRangeFilter(**cvss))

    if "date" in filters and filters["date"] and isinstance(filters["date"], dict):
        active_filters.append(DateFilter(**filters["date"]))

    filtered = []
    for record in results:
        match_all = True
        for f in active_filters:
            if not f.apply(record):
                match_all = False
                break
        if match_all:
            filtered.append(record)

    return filtered


def validate_filters(filters: dict[str, Any] | None) -> None:
    """Validate filter dictionary format."""
    if not filters:
        return

    if "severity" in filters and filters["severity"]:
        sev = filters["severity"]
        level = sev.get("level") if isinstance(sev, dict) else sev
        if level:
            valid_levels = SeverityFilter.SEVERITY_LEVELS
            if str(level).upper() not in valid_levels:
                raise ValidationError(
                    field="severity",
                    value=str(level),
                    message=f"Severity level must be one of: {', '.join(valid_levels)}",
                )

    if "date" in filters and filters["date"] and isinstance(filters["date"], dict):
        from utils.time import parse_date

        for k in [
            "published_since",
            "published_before",
            "updated_since",
            "updated_before",
        ]:
            val = filters["date"].get(k)
            if val and not parse_date(str(val)):
                raise ValidationError(
                    field=f"date.{k}",
                    value=str(val),
                    message="Invalid date string format",
                )
