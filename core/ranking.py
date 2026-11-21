"""
Result Ranking and Sorting.

Purpose: Rank CVE results by various criteria for better relevance ordering.
Inputs: List of CVE records, sort criteria dictionary.
Outputs: Sorted result list ordered by priority.
Responsibilities: Implement ranking algorithms (EPSS, exploit availability, CVSS score).
Dependencies: utils.errors.ValidationError, datetime for time calculations.
"""

from typing import Any


class BaseRanker:
    """Base class for ranking algorithms."""

    def __init__(self):
        self.name = "base_ranker"

    def rank(
        self, results: list[dict[str, Any]], reverse: bool = True
    ) -> list[dict[str, Any]]:
        """Apply ranking to a result set. Returns sorted list."""
        raise NotImplementedError


class EPSSRanker(BaseRanker):
    """Rank CVEs by exploitation probability (EPSS scores)."""

    def __init__(self):
        super().__init__()
        self.name = "epss_ranker"

    def rank(
        self, results: list[dict[str, Any]], reverse: bool = True
    ) -> list[dict[str, Any]]:
        if not results:
            return []

        scored = []
        for record in results:
            score = self._get_epss_score(record)
            scored.append((score, record))

        scored.sort(key=lambda x: x[0], reverse=reverse)
        return [record for _, record in scored]

    def _get_epss_score(self, record: dict[str, Any]) -> float:
        epss = record.get("epss") or record.get("exploit_probability") or 0.0

        if isinstance(epss, str):
            try:
                epss = float(epss.strip())
            except ValueError:
                epss = 0.0

        if not isinstance(epss, (int, float)):
            epss = 0.0

        if epss > 1.0:
            epss = epss / 100.0

        return max(0.0, min(1.0, float(epss)))


class ExploitRanker(BaseRanker):
    """Prioritize CVEs with known exploits available."""

    def __init__(self):
        super().__init__()
        self.name = "exploit_ranker"

    def rank(
        self, results: list[dict[str, Any]], reverse: bool = True
    ) -> list[dict[str, Any]]:
        if not results:
            return []

        scored = []
        for record in results:
            has_exploit = self._has_exploit(record)
            scored.append((1.0 if has_exploit else 0.0, record))

        scored.sort(key=lambda x: x[0], reverse=reverse)
        return [record for _, record in scored]

    def _has_exploit(self, record: dict[str, Any]) -> bool:
        value = record.get("exploit_available") or record.get("exploits_available")
        if isinstance(value, bool):
            return value

        if isinstance(value, str):
            return value.lower().strip() in ("true", "yes", "available", "1")

        return False


class CVSSRanker(BaseRanker):
    """Sort CVEs by CVSS severity score."""

    def __init__(self):
        super().__init__()
        self.name = "cvss_ranker"

    def rank(
        self, results: list[dict[str, Any]], reverse: bool = True
    ) -> list[dict[str, Any]]:
        if not results:
            return []

        scored = []
        for record in results:
            score = self._get_cvss_score(record)
            scored.append((score, record))

        scored.sort(key=lambda x: x[0], reverse=reverse)
        return [record for _, record in scored]

    def _get_cvss_score(self, record: dict[str, Any]) -> float:
        cvss = record.get("cvss") or record.get("cvss_score") or 0.0

        if isinstance(cvss, str):
            try:
                cvss = float(cvss.strip())
            except ValueError:
                cvss = 0.0

        if not isinstance(cvss, (int, float)):
            cvss = 0.0

        return max(0.0, min(10.0, float(cvss)))


def rank_results(
    results: list[dict[str, Any]], sort_by: str, reverse: bool = True
) -> list[dict[str, Any]]:
    """Main ranking function to sort results by specified criterion."""
    if not results:
        return []

    if not sort_by:
        return results

    sort_key = sort_by.lower().strip()

    ranker: BaseRanker
    if sort_key in ("epss", "exploit_probability"):
        ranker = EPSSRanker()
    elif sort_key in ("exploit", "has_exploit", "exploit_available"):
        ranker = ExploitRanker()
    elif sort_key in ("cvss", "severity", "cvss_score"):
        ranker = CVSSRanker()
    else:
        # Default to CVSS score sort if unknown
        ranker = CVSSRanker()

    return ranker.rank(results, reverse=reverse)
