"""
System repositories: user settings, audit log, source refresh state, metrics.

Privacy rule: these tables never receive free-text user input (usernames,
target domains, generated queries). Callers pass identifiers and enums only.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, func

from storage.database import (
    AuditLogRecord,
    MetricRecord,
    SourceStateRecord,
    UserSettingRecord,
    get_session,
    utcnow,
)
from utils.errors import DatabaseError


class SettingsRepository:
    def get(self, key: str, default: Any = None) -> Any:
        try:
            with get_session() as session:
                row = session.get(UserSettingRecord, key)
                return json.loads(row.value_json or "null") if row else default
        except Exception as error:
            raise DatabaseError("settings_get", error) from error

    def set(self, key: str, value: Any) -> None:
        try:
            with get_session() as session:
                row = session.get(UserSettingRecord, key)
                if row is None:
                    session.add(
                        UserSettingRecord(key=key, value_json=json.dumps(value))
                    )
                else:
                    row.value_json = json.dumps(value)
        except Exception as error:
            raise DatabaseError("settings_set", error) from error

    def all(self) -> dict[str, Any]:
        with get_session() as session:
            return {
                row.key: json.loads(row.value_json or "null")
                for row in session.query(UserSettingRecord).all()
            }

    def delete(self, key: str) -> bool:
        with get_session() as session:
            row = session.get(UserSettingRecord, key)
            if row is None:
                return False
            session.delete(row)
            return True


class AuditRepository:
    def record(
        self,
        event: str,
        object_kind: str = "",
        object_id: str = "",
        risk_level: str = "",
        details: dict[str, Any] | None = None,
    ) -> int:
        try:
            with get_session() as session:
                row = AuditLogRecord(
                    event=event,
                    object_kind=object_kind,
                    object_id=str(object_id),
                    risk_level=risk_level,
                    details_json=json.dumps(details or {}, default=str),
                )
                session.add(row)
                session.flush()
                return int(row.id)
        except Exception as error:
            raise DatabaseError("audit_record", error) from error

    def list(self, limit: int = 100, event: str | None = None) -> list[dict[str, Any]]:
        with get_session() as session:
            query = session.query(AuditLogRecord)
            if event:
                query = query.filter(AuditLogRecord.event == event)
            rows = query.order_by(AuditLogRecord.id.desc()).limit(limit).all()
            return [
                {
                    "id": row.id,
                    "ts": row.ts.isoformat() if row.ts else "",
                    "event": row.event,
                    "object_kind": row.object_kind,
                    "object_id": row.object_id,
                    "risk_level": row.risk_level,
                    "details": json.loads(row.details_json or "{}"),
                }
                for row in rows
            ]

    def purge_older_than(self, days: int) -> int:
        cutoff = utcnow() - timedelta(days=days)
        with get_session() as session:
            result = session.execute(
                delete(AuditLogRecord).where(AuditLogRecord.ts < cutoff)
            )
            return int(result.rowcount or 0)  # type: ignore[attr-defined]

    def purge_all(self) -> int:
        with get_session() as session:
            result = session.execute(delete(AuditLogRecord))
            return int(result.rowcount or 0)  # type: ignore[attr-defined]


class SourceStateRepository:
    def get(self, source: str) -> dict[str, Any]:
        with get_session() as session:
            row = session.get(SourceStateRecord, source)
            if row is None:
                return {
                    "source": source,
                    "last_success": None,
                    "last_attempt": None,
                    "etag": "",
                    "last_modified": "",
                    "status": "never",
                    "error": "",
                    "row_count": 0,
                }
            return {
                "source": row.source,
                "last_success": row.last_success,
                "last_attempt": row.last_attempt,
                "etag": row.etag or "",
                "last_modified": row.last_modified or "",
                "status": row.status or "never",
                "error": row.error or "",
                "row_count": int(row.row_count or 0),
            }

    def update(self, source: str, **fields: Any) -> None:
        with get_session() as session:
            row = session.get(SourceStateRecord, source)
            if row is None:
                row = SourceStateRecord(source=source)
                session.add(row)
            for key, value in fields.items():
                setattr(row, key, value)

    def mark_attempt(self, source: str) -> None:
        self.update(source, last_attempt=utcnow(), status="running")

    def mark_success(self, source: str, row_count: int | None = None, **extra) -> None:
        fields: dict[str, Any] = {
            "last_success": utcnow(),
            "last_attempt": utcnow(),
            "status": "ok",
            "error": "",
            **extra,
        }
        if row_count is not None:
            fields["row_count"] = row_count
        self.update(source, **fields)

    def mark_failure(self, source: str, error: str) -> None:
        self.update(source, last_attempt=utcnow(), status="error", error=error[:500])

    def is_stale(self, source: str, ttl_hours: float) -> bool:
        state = self.get(source)
        last = state["last_success"]
        return last is None or utcnow() - last > timedelta(hours=ttl_hours)

    def all(self) -> list[dict[str, Any]]:
        with get_session() as session:
            names = [row.source for row in session.query(SourceStateRecord).all()]
        return [self.get(name) for name in names]


class MetricsRepository:
    def record(self, name: str, value: float = 1.0, **tags: Any) -> None:
        with get_session() as session:
            session.add(
                MetricRecord(name=name, value=float(value), tags_json=json.dumps(tags))
            )

    def summary(self, days: int = 30) -> list[dict[str, Any]]:
        cutoff = utcnow() - timedelta(days=days)
        with get_session() as session:
            rows = (
                session.query(
                    MetricRecord.name,
                    func.count(MetricRecord.id),
                    func.avg(MetricRecord.value),
                    func.max(MetricRecord.value),
                )
                .filter(MetricRecord.ts >= cutoff)
                .group_by(MetricRecord.name)
                .order_by(MetricRecord.name)
                .all()
            )
            return [
                {
                    "name": name,
                    "count": count,
                    "avg": float(avg or 0),
                    "max": float(mx or 0),
                }
                for name, count, avg, mx in rows
            ]

    def purge_older_than(self, days: int) -> int:
        cutoff = utcnow() - timedelta(days=days)
        with get_session() as session:
            result = session.execute(
                delete(MetricRecord).where(MetricRecord.ts < cutoff)
            )
            return int(result.rowcount or 0)  # type: ignore[attr-defined]
