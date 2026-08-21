from typing import Any

from sqlalchemy import desc, func, or_

from core.models import CVEModel
from storage.database import (
    CVERecord,
    WatchlistItemRecord,
    get_session,
    map_model_to_record,
    map_record_to_model,
)
from utils.errors import DatabaseError


class CVERepository:
    def save(self, cve: CVEModel) -> CVEModel:
        try:
            with get_session() as session:
                record = session.get(CVERecord, cve.id)
                fresh = map_model_to_record(cve)
                if record is None:
                    session.add(fresh)
                    session.flush()
                    return map_record_to_model(fresh)
                for field in (
                    "summary",
                    "severity",
                    "cvss_score",
                    "vector",
                    "published_date",
                    "updated_date",
                    "kev_date",
                    "exploit_available",
                    "epss_score",
                    "epss_percentile",
                    "vendor",
                    "cwe_id",
                    "cwe_name",
                    "tags_json",
                    "references_json",
                    "affected_products_json",
                    "sources_json",
                    "fetched_at",
                ):
                    setattr(record, field, getattr(fresh, field))
                session.flush()
                return map_record_to_model(record)
        except Exception as error:
            raise DatabaseError("save", error) from error

    def save_bulk(self, cves: list[CVEModel]) -> int:
        for cve in cves:
            self.save(cve)
        return len(cves)

    def get_by_id(self, cve_id: str) -> CVEModel | None:
        try:
            with get_session() as session:
                record = session.get(CVERecord, cve_id.strip().upper())
                return map_record_to_model(record) if record else None
        except Exception as error:
            raise DatabaseError("get_by_id", error) from error

    def delete(self, cve_id: str) -> bool:
        try:
            with get_session() as session:
                record = session.get(CVERecord, cve_id.strip().upper())
                if not record:
                    return False
                session.delete(record)
                return True
        except Exception as error:
            raise DatabaseError("delete", error) from error

    def search(
        self,
        query: str = "",
        severity: str | None = None,
        cvss_min: float = 0.0,
        vendor: str | None = None,
        cwe_id: str | None = None,
        exploit_only: bool = False,
        limit: int = 100,
        offset: int = 0,
        sort_by: str = "published_date",
        reverse: bool = True,
    ) -> list[CVEModel]:
        try:
            with get_session() as session:
                rows = session.query(CVERecord)
                if query:
                    pattern = f"%{query.strip()}%"
                    rows = rows.filter(
                        or_(
                            CVERecord.id.ilike(pattern),
                            CVERecord.summary.ilike(pattern),
                            CVERecord.vendor.ilike(pattern),
                        )
                    )
                if severity:
                    rows = rows.filter(CVERecord.severity.ilike(severity.strip()))
                if cvss_min > 0:
                    rows = rows.filter(CVERecord.cvss_score >= cvss_min)
                if vendor:
                    rows = rows.filter(CVERecord.vendor.ilike(f"%{vendor.strip()}%"))
                if cwe_id:
                    rows = rows.filter(CVERecord.cwe_id.ilike(f"%{cwe_id.strip()}%"))
                if exploit_only:
                    rows = rows.filter(CVERecord.exploit_available.is_(True))
                sort_column = getattr(CVERecord, sort_by, CVERecord.published_date)
                rows = rows.order_by(desc(sort_column) if reverse else sort_column)
                return [
                    map_record_to_model(row)
                    for row in rows.offset(offset).limit(limit).all()
                ]
        except Exception as error:
            raise DatabaseError("search", error) from error

    def get_stats(self) -> dict[str, Any]:
        try:
            with get_session() as session:

                def count(*filters):
                    query = session.query(func.count(CVERecord.id))
                    for item in filters:
                        query = query.filter(item)
                    return query.scalar() or 0

                return {
                    "total_cves": count(),
                    "critical": count(CVERecord.severity == "Critical"),
                    "high": count(CVERecord.severity == "High"),
                    "medium": count(CVERecord.severity == "Medium"),
                    "low": count(CVERecord.severity == "Low"),
                    "exploits_available": count(CVERecord.exploit_available.is_(True)),
                }
        except Exception as error:
            raise DatabaseError("get_stats", error) from error


class WatchlistRepository:
    def add(
        self, target_type: str, target_value: str, notes: str = ""
    ) -> dict[str, Any]:
        try:
            with get_session() as session:
                record = WatchlistItemRecord(
                    target_type=target_type, target_value=target_value, notes=notes
                )
                session.add(record)
                session.flush()
                return {
                    "id": record.id,
                    "target_type": record.target_type,
                    "target_value": record.target_value,
                    "created_at": record.created_at.isoformat()
                    if record.created_at
                    else "",
                    "notes": record.notes,
                }
        except Exception as error:
            raise DatabaseError("watchlist_add", error) from error

    def list_all(self) -> list[dict[str, Any]]:
        try:
            with get_session() as session:
                rows = session.query(WatchlistItemRecord).all()
                return [
                    {
                        "id": row.id,
                        "target_type": row.target_type,
                        "target_value": row.target_value,
                        "created_at": row.created_at.isoformat()
                        if row.created_at
                        else "",
                        "notes": row.notes,
                    }
                    for row in rows
                ]
        except Exception as error:
            raise DatabaseError("watchlist_list", error) from error

    def remove(self, item_id: str) -> bool:
        try:
            with get_session() as session:
                row = (
                    session.query(WatchlistItemRecord)
                    .filter(
                        or_(
                            WatchlistItemRecord.id == item_id,
                            WatchlistItemRecord.target_value == item_id,
                        )
                    )
                    .first()
                )
                if not row:
                    return False
                session.delete(row)
                return True
        except Exception as error:
            raise DatabaseError("watchlist_remove", error) from error
