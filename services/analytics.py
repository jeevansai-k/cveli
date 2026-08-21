from storage.repositories import CVERepository


class AnalyticsService:
    def __init__(self, repo: CVERepository | None = None) -> None:
        self.repo = repo or CVERepository()

    def get_summary_stats(self) -> dict[str, int]:
        return self.repo.get_stats()
