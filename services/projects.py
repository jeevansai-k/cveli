"""Research projects: group CVEs, exploit references, saved dorks and reports."""

from __future__ import annotations

from typing import Any

from services.audit import audit
from storage.research_repositories import (
    DorkRepository,
    ProjectRepository,
    ReportRepository,
    SavedSearchRepository,
    purge_research_data,
)
from storage.system_repositories import AuditRepository
from utils.errors import ValidationError


class ProjectService:
    def __init__(self) -> None:
        self.projects = ProjectRepository()
        self.dorks = DorkRepository()
        self.reports = ReportRepository()
        self.searches = SavedSearchRepository()

    def create(self, name: str, notes: str = "") -> dict[str, Any]:
        project = self.projects.create(name, notes)
        audit("project_created", object_kind="project", object_id=project["id"])
        return project

    def list(self) -> list[dict[str, Any]]:
        out = []
        for project in self.projects.list():
            items = self.projects.items(project["id"])
            dorks = self.dorks.list(project["id"])
            out.append({**project, "item_count": len(items), "dork_count": len(dorks)})
        return out

    def show(self, ref: str) -> dict[str, Any]:
        project = self.projects.require(ref)
        return {
            **project,
            "items": self.projects.items(project["id"]),
            "dorks": self.dorks.list(project["id"]),
        }

    def add(self, ref: str, kind: str, item_id: str, note: str = "") -> dict[str, Any]:
        project = self.projects.require(ref)
        item_id = item_id.strip()
        if kind == "cve":
            from core.validator import validate_cve_id

            validate_cve_id(item_id)
            item_id = item_id.upper()
        elif kind == "exploit":
            digits = item_id.upper().removeprefix("EDB-")
            if not digits.isdigit():
                raise ValidationError("edb_id", item_id, "EDB-ID must be numeric")
            item_id = digits
        return self.projects.add_item(project["id"], kind, item_id, note)

    def save_dork(self, ref: str, dork: dict[str, Any]) -> dict[str, Any]:
        """Persist a dork (the only path that stores usernames/domains)."""
        project = self.projects.get(ref) or self.projects.create(ref)
        saved = self.dorks.save(project["id"], dork)
        audit(
            "dork_saved",
            object_kind="dork_template",
            object_id=dork["id"],
            risk_level=dork.get("risk_level", ""),
            project_id=project["id"],
        )
        return saved

    def delete(self, ref: str) -> bool:
        project = self.projects.get(ref)
        if project is None:
            return False
        deleted = self.projects.delete(project["id"])
        if deleted:
            audit("project_deleted", object_kind="project", object_id=project["id"])
        return deleted

    def purge_all(self) -> int:
        removed = purge_research_data()
        removed += AuditRepository().purge_all()
        audit("privacy_purge", count=removed)
        return removed
