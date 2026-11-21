"""
Research workspace repositories: projects, project items, saved dorks,
generated reports and saved searches.

These are the only tables that may hold user-entered research inputs
(usernames, target domains, queries) — and only after an explicit "save".
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import delete

from storage.database import (
    DorkSavedRecord,
    GeneratedReportRecord,
    ProjectItemRecord,
    ProjectRecord,
    SavedSearchRecord,
    get_session,
    utcnow,
)
from utils.errors import DatabaseError, ValidationError


def _iso(value) -> str:
    return value.isoformat(timespec="seconds") if value else ""


class ProjectRepository:
    def create(self, name: str, notes: str = "") -> dict[str, Any]:
        cleaned = name.strip()
        if not cleaned or len(cleaned) > 128:
            raise ValidationError("name", name, "Project name must be 1-128 characters")
        with get_session() as session:
            if session.query(ProjectRecord).filter_by(name=cleaned).first():
                raise ValidationError("name", name, f"Project '{cleaned}' exists")
            row = ProjectRecord(name=cleaned, notes=notes)
            session.add(row)
            session.flush()
            return self._row(row)

    @staticmethod
    def _row(row: ProjectRecord) -> dict[str, Any]:
        return {
            "id": row.id,
            "name": row.name,
            "notes": row.notes or "",
            "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at),
        }

    def get(self, ref: str) -> dict[str, Any] | None:
        with get_session() as session:
            row = session.get(ProjectRecord, ref) or (
                session.query(ProjectRecord).filter_by(name=ref.strip()).first()
            )
            return self._row(row) if row else None

    def require(self, ref: str) -> dict[str, Any]:
        project = self.get(ref)
        if project is None:
            raise ValidationError("project", ref, f"Project '{ref}' not found")
        return project

    def get_or_create(self, name: str) -> dict[str, Any]:
        return self.get(name) or self.create(name)

    def list(self) -> list[dict[str, Any]]:
        with get_session() as session:
            rows = session.query(ProjectRecord).order_by(ProjectRecord.created_at).all()
            return [self._row(row) for row in rows]

    def add_item(
        self, project_id: str, kind: str, ref_id: str, note: str = ""
    ) -> dict[str, Any]:
        if kind not in {"cve", "exploit", "dork", "report", "search"}:
            raise ValidationError("kind", kind, "Unknown project item kind")
        with get_session() as session:
            existing = (
                session.query(ProjectItemRecord)
                .filter_by(project_id=project_id, kind=kind, ref_id=ref_id)
                .first()
            )
            if existing:
                return {"id": existing.id, "kind": kind, "ref_id": ref_id}
            row = ProjectItemRecord(
                project_id=project_id, kind=kind, ref_id=ref_id, note=note
            )
            session.add(row)
            session.flush()
            project = session.get(ProjectRecord, project_id)
            if project is not None:
                project.updated_at = utcnow()
            return {"id": row.id, "kind": kind, "ref_id": ref_id}

    def items(self, project_id: str) -> list[dict[str, Any]]:
        with get_session() as session:
            rows = (
                session.query(ProjectItemRecord)
                .filter_by(project_id=project_id)
                .order_by(ProjectItemRecord.created_at)
                .all()
            )
            return [
                {
                    "id": row.id,
                    "kind": row.kind,
                    "ref_id": row.ref_id,
                    "note": row.note or "",
                    "created_at": _iso(row.created_at),
                }
                for row in rows
            ]

    def delete(self, project_id: str) -> bool:
        with get_session() as session:
            row = session.get(ProjectRecord, project_id)
            if row is None:
                return False
            session.execute(
                delete(ProjectItemRecord).where(
                    ProjectItemRecord.project_id == project_id
                )
            )
            session.execute(
                delete(DorkSavedRecord).where(DorkSavedRecord.project_id == project_id)
            )
            session.query(GeneratedReportRecord).filter_by(
                project_id=project_id
            ).update({GeneratedReportRecord.project_id: None})
            session.delete(row)
            return True


class DorkRepository:
    def save(self, project_id: str, dork: dict[str, Any]) -> dict[str, Any]:
        try:
            with get_session() as session:
                row = DorkSavedRecord(
                    project_id=project_id,
                    template_id=dork["id"],
                    category=dork["category"],
                    target_domain=dork.get("target_domain", ""),
                    username=dork.get("username", ""),
                    query=dork["query"],
                    risk_level=dork.get("risk_level", "low"),
                )
                session.add(row)
                session.flush()
                return {"id": row.id, **dork}
        except Exception as error:
            raise DatabaseError("dork_save", error) from error

    def list(self, project_id: str | None = None) -> list[dict[str, Any]]:
        with get_session() as session:
            query = session.query(DorkSavedRecord)
            if project_id:
                query = query.filter_by(project_id=project_id)
            return [
                {
                    "id": row.id,
                    "project_id": row.project_id,
                    "template_id": row.template_id,
                    "category": row.category,
                    "target_domain": row.target_domain,
                    "username": row.username,
                    "query": row.query,
                    "risk_level": row.risk_level,
                    "created_at": _iso(row.created_at),
                }
                for row in query.order_by(DorkSavedRecord.created_at).all()
            ]

    def delete(self, dork_id: str) -> bool:
        with get_session() as session:
            row = session.get(DorkSavedRecord, dork_id)
            if row is None:
                return False
            session.delete(row)
            return True


class ReportRepository:
    def record(
        self,
        module_type: str,
        formats: list[str],
        paths: list[str],
        cve_id: str | None = None,
        edb_id: int | None = None,
        project_id: str | None = None,
    ) -> dict[str, Any]:
        with get_session() as session:
            row = GeneratedReportRecord(
                project_id=project_id,
                cve_id=cve_id,
                edb_id=edb_id,
                module_type=module_type,
                formats_json=json.dumps(formats),
                paths_json=json.dumps(paths),
            )
            session.add(row)
            session.flush()
            return {"id": row.id, "created_at": _iso(row.created_at)}

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        with get_session() as session:
            rows = (
                session.query(GeneratedReportRecord)
                .order_by(GeneratedReportRecord.created_at.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": row.id,
                    "project_id": row.project_id,
                    "cve_id": row.cve_id,
                    "edb_id": row.edb_id,
                    "module_type": row.module_type,
                    "formats": json.loads(row.formats_json or "[]"),
                    "paths": json.loads(row.paths_json or "[]"),
                    "created_at": _iso(row.created_at),
                }
                for row in rows
            ]


class SavedSearchRepository:
    def save(self, name: str, kind: str, params: dict[str, Any]) -> dict[str, Any]:
        cleaned = name.strip()
        if not cleaned or len(cleaned) > 64:
            raise ValidationError("name", name, "Name must be 1-64 characters")
        if kind not in {"cve", "exploit"}:
            raise ValidationError("kind", kind, "kind must be cve or exploit")
        with get_session() as session:
            row = session.query(SavedSearchRecord).filter_by(name=cleaned).first()
            if row is None:
                row = SavedSearchRecord(name=cleaned, kind=kind)
                session.add(row)
            row.kind = kind
            row.params_json = json.dumps(params, default=str)
            session.flush()
            return {"id": row.id, "name": cleaned, "kind": kind, "params": params}

    def get(self, name: str) -> dict[str, Any] | None:
        with get_session() as session:
            row = session.query(SavedSearchRecord).filter_by(name=name.strip()).first()
            if row is None:
                return None
            return {
                "id": row.id,
                "name": row.name,
                "kind": row.kind,
                "params": json.loads(row.params_json or "{}"),
            }

    def list(self, kind: str | None = None) -> list[dict[str, Any]]:
        with get_session() as session:
            query = session.query(SavedSearchRecord)
            if kind:
                query = query.filter_by(kind=kind)
            return [
                {
                    "id": row.id,
                    "name": row.name,
                    "kind": row.kind,
                    "params": json.loads(row.params_json or "{}"),
                    "created_at": _iso(row.created_at),
                }
                for row in query.order_by(SavedSearchRecord.name).all()
            ]

    def delete(self, name: str) -> bool:
        with get_session() as session:
            row = session.query(SavedSearchRecord).filter_by(name=name.strip()).first()
            if row is None:
                return False
            session.delete(row)
            return True


def purge_research_data() -> int:
    """Delete every saved research artefact (privacy purge)."""
    removed = 0
    with get_session() as session:
        for model in (
            DorkSavedRecord,
            ProjectItemRecord,
            ProjectRecord,
            SavedSearchRecord,
            GeneratedReportRecord,
        ):
            result = session.execute(delete(model))
            removed += int(result.rowcount or 0)  # type: ignore[attr-defined]
    return removed
