"""
CVE and watchlist repositories.

Fix B1: saves merge field-by-field into the stored row (``core.merge``) instead
of overwriting every column, so partial KEV/EPSS records never erase NVD data.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import and_, desc, func, or_

from core.merge import merge_models
from core.models import CVEModel
from storage.database import (
    CVERecord,
    WatchlistItemRecord,
    get_session,
    map_model_to_record,
    map_record_to_model,
    utcnow,
)
from utils.errors import DatabaseError

_COPY_FIELDS = (
    "summary",
    "severity",
    "cvss_score",
    "vector",
    "published_date",
    "updated_date",
    "kev_date",
    "exploit_available",
    "kev",
    "public_exploit_count",
    "epss_score",
    "epss_percentile",
    "vendor",
    "cwe_id",
    "cwe_name",
    "tags_json",
    "references_json",
    "reference_details_json",
    "affected_products_json",
    "sources_json",
    "fetched_at",
)

SORT_COLUMNS = {
    "published": CVERecord.published_date,
    "published_date": CVERecord.published_date,
    "updated": CVERecord.updated_date,
    "cvss": CVERecord.cvss_score,
    "epss": CVERecord.epss_score,
    "id": CVERecord.id,
    "first_seen": CVERecord.first_seen_at,
}


def _parse_bound(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00").split(".")[0])
    except ValueError:
        return None
    return parsed.replace(tzinfo=None)


class CVERepository:
    def _upsert(self, session, cve: CVEModel) -> CVERecord:
        record = session.get(CVERecord, cve.id)
        if record is None:
            fresh = map_model_to_record(cve)
            fresh.first_seen_at = utcnow()
            session.add(fresh)
            return fresh
        merged = merge_models(map_record_to_model(record), cve)
        if not merged.fetched_at:
            merged.fetched_at = utcnow().strftime("%Y-%m-%d")
        fresh = map_model_to_record(merged)
        fresh.fetched_at = utcnow()
        for field in _COPY_FIELDS:
            setattr(record, field, getattr(fresh, field))
        return record

    def save(self, cve: CVEModel) -> CVEModel:
        try:
            with get_session() as session:
                record = self._upsert(session, cve)
                session.flush()
                return map_record_to_model(record)
        except Exception as error:
            raise DatabaseError("save", error) from error

    def save_bulk(self, cves: list[CVEModel]) -> int:
        """Merge-save many records in a single transaction."""
        if not cves:
            return 0
        try:
            with get_session() as session:
                for cve in cves:
                    self._upsert(session, cve)
                    session.flush()
            return len(cves)
        except Exception as error:
            raise DatabaseError("save_bulk", error) from error

    def get_by_id(self, cve_id: str) -> CVEModel | None:
        try:
            with get_session() as session:
                record = session.get(CVERecord, cve_id.strip().upper())
                return map_record_to_model(record) if record else None
        except Exception as error:
            raise DatabaseError("get_by_id", error) from error

    def get_many(self, cve_ids: list[str]) -> list[CVEModel]:
        ids = [cve_id.strip().upper() for cve_id in cve_ids if cve_id]
        if not ids:
            return []
        with get_session() as session:
            rows = session.query(CVERecord).filter(CVERecord.id.in_(ids)).all()
            return [map_record_to_model(row) for row in rows]

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
        published_since: str | None = None,
        published_until: str | None = None,
        kev_only: bool = False,
        public_exploit_only: bool = False,
        first_seen_after: datetime | None = None,
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
                            CVERecord.affected_products_json.ilike(pattern),
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
                if kev_only:
                    rows = rows.filter(CVERecord.kev.is_(True))
                if public_exploit_only:
                    rows = rows.filter(CVERecord.public_exploit_count > 0)
                if first_seen_after is not None:
                    rows = rows.filter(CVERecord.first_seen_at > first_seen_after)
                since = _parse_bound(published_since)
                until = _parse_bound(published_until)
                if since or until:
                    pub_conditions = [CVERecord.published_date.isnot(None)]
                    kev_conditions = [
                        CVERecord.published_date.is_(None),
                        CVERecord.kev_date.isnot(None),
                    ]
                    if since:
                        pub_conditions.append(CVERecord.published_date >= since)
                        kev_conditions.append(CVERecord.kev_date >= since)
                    if until:
                        pub_conditions.append(CVERecord.published_date <= until)
                        kev_conditions.append(CVERecord.kev_date <= until)
                    rows = rows.filter(
                        or_(
                            and_(*pub_conditions),
                            and_(*kev_conditions),
                            # undated records cannot be proven out of range
                            and_(
                                CVERecord.published_date.is_(None),
                                CVERecord.kev_date.is_(None),
                            ),
                        )
                    )
                sort_column = SORT_COLUMNS.get(sort_by, CVERecord.published_date)
                ordering = desc(sort_column) if reverse else sort_column
                rows = rows.order_by(ordering.nulls_last(), desc(CVERecord.id))
                return [
                    map_record_to_model(row)
                    for row in rows.offset(offset).limit(limit).all()
                ]
        except Exception as error:
            raise DatabaseError("search", error) from error

    def update_public_exploit_counts(self, counts: dict[str, int]) -> int:
        """Set ``public_exploit_count`` for stored CVEs (index rebuild)."""
        with get_session() as session:
            session.query(CVERecord).filter(CVERecord.public_exploit_count > 0).update(
                {CVERecord.public_exploit_count: 0}, synchronize_session=False
            )
            updated = 0
            for cve_id, count in counts.items():
                updated += (
                    session.query(CVERecord)
                    .filter(CVERecord.id == cve_id)
                    .update(
                        {
                            CVERecord.public_exploit_count: count,
                            CVERecord.exploit_available: True,
                        },
                        synchronize_session=False,
                    )
                )
            return updated

    def all_ids(self, limit: int | None = None) -> list[str]:
        with get_session() as session:
            query = session.query(CVERecord.id).order_by(desc(CVERecord.fetched_at))
            if limit:
                query = query.limit(limit)
            return [row[0] for row in query.all()]

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
                    "unscored": count(CVERecord.severity.is_(None)),
                    "kev": count(CVERecord.kev.is_(True)),
                    "public_exploits": count(CVERecord.public_exploit_count > 0),
                    "exploits_available": count(CVERecord.exploit_available.is_(True)),
                }
        except Exception as error:
            raise DatabaseError("get_stats", error) from error


def _watch_row(row: WatchlistItemRecord) -> dict[str, Any]:
    return {
        "id": row.id,
        "target_type": row.target_type,
        "target_value": row.target_value,
        "created_at": row.created_at.isoformat() if row.created_at else "",
        "notes": row.notes or "",
        "last_checked_at": row.last_checked_at.isoformat()
        if row.last_checked_at
        else "",
    }


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
                return _watch_row(record)
        except Exception as error:
            raise DatabaseError("watchlist_add", error) from error

    def list_all(self) -> list[dict[str, Any]]:
        try:
            with get_session() as session:
                rows = (
                    session.query(WatchlistItemRecord)
                    .order_by(WatchlistItemRecord.created_at)
                    .all()
                )
                return [_watch_row(row) for row in rows]
        except Exception as error:
            raise DatabaseError("watchlist_list", error) from error

    def mark_checked(self, item_id: str, when: datetime | None = None) -> None:
        with get_session() as session:
            row = session.get(WatchlistItemRecord, item_id)
            if row is not None:
                row.last_checked_at = when or utcnow()

    def remove(self, item_id: str) -> bool:
        try:
            with get_session() as session:
                row = (
                    session.query(WatchlistItemRecord)
                    .filter(
                        or_(
                            WatchlistItemRecord.id == item_id,
                            WatchlistItemRecord.id.like(f"{item_id}%")
                            if len(item_id) >= 6
                            else WatchlistItemRecord.id == item_id,
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
