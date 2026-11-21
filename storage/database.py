"""
SQLite persistence layer.

Purpose: ORM table definitions, engine/session management, model <-> row mapping.
Storage location comes from ``config.settings`` (XDG data dir by default,
``CVELI_DB_PATH`` to override). Schema changes run through
``storage.migrations`` (versioned, with an automatic pre-migration backup).
"""

from __future__ import annotations

import json
import shutil
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from core.models import CWEID, CVEModel, Reference


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return uuid.uuid4().hex


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class CVERecord(Base):
    __tablename__ = "cves"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str | None] = mapped_column(String(20), index=True, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, index=True, nullable=True)
    vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    published_date: Mapped[datetime | None] = mapped_column(
        DateTime, index=True, nullable=True
    )
    updated_date: Mapped[datetime | None] = mapped_column(
        DateTime, index=True, nullable=True
    )
    kev_date: Mapped[datetime | None] = mapped_column(
        DateTime, index=True, nullable=True
    )
    exploit_available: Mapped[bool | None] = mapped_column(
        Boolean, default=False, index=True, nullable=True
    )
    kev: Mapped[bool | None] = mapped_column(
        Boolean, default=False, index=True, nullable=True
    )
    public_exploit_count: Mapped[int | None] = mapped_column(
        Integer, default=0, index=True, nullable=True
    )
    epss_score: Mapped[float | None] = mapped_column(Float, index=True, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(
        Float, index=True, nullable=True
    )
    vendor: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    cwe_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    tags_json: Mapped[str | None] = mapped_column(Text, default="[]", nullable=True)
    references_json: Mapped[str | None] = mapped_column(
        Text, default="[]", nullable=True
    )
    reference_details_json: Mapped[str | None] = mapped_column(
        Text, default="[]", nullable=True
    )
    affected_products_json: Mapped[str | None] = mapped_column(
        Text, default="[]", nullable=True
    )
    sources_json: Mapped[str | None] = mapped_column(Text, default="[]", nullable=True)
    fetched_at: Mapped[datetime | None] = mapped_column(
        DateTime, index=True, nullable=True
    )
    first_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime, index=True, nullable=True
    )


class WatchlistItemRecord(Base):
    __tablename__ = "watchlists"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    target_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    target_value: Mapped[str] = mapped_column(String(256), index=True, nullable=False)
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime, default=utcnow, nullable=True
    )
    notes: Mapped[str | None] = mapped_column(Text, default="", nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ExploitRecord(Base):
    __tablename__ = "exploits"

    edb_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    title: Mapped[str] = mapped_column(Text, nullable=False, default="")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    author: Mapped[str | None] = mapped_column(
        String(256), index=True, default="", nullable=True
    )
    platform: Mapped[str | None] = mapped_column(
        String(64), index=True, default="", nullable=True
    )
    type: Mapped[str | None] = mapped_column(
        String(32), index=True, default="", nullable=True
    )
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    date_published: Mapped[str | None] = mapped_column(
        String(10), index=True, default="", nullable=True
    )
    date_added: Mapped[str | None] = mapped_column(
        String(10), default="", nullable=True
    )
    date_updated: Mapped[str | None] = mapped_column(
        String(10), default="", nullable=True
    )
    verified: Mapped[bool | None] = mapped_column(
        Boolean, index=True, default=False, nullable=True
    )
    file_path: Mapped[str | None] = mapped_column(
        String(512), default="", nullable=True
    )
    advisory_url: Mapped[str | None] = mapped_column(Text, default="", nullable=True)
    tags_json: Mapped[str | None] = mapped_column(Text, default="[]", nullable=True)
    aliases_json: Mapped[str | None] = mapped_column(Text, default="[]", nullable=True)
    cve_ids_json: Mapped[str | None] = mapped_column(Text, default="[]", nullable=True)
    affected_product: Mapped[str | None] = mapped_column(
        String(256), index=True, nullable=True
    )
    affected_versions_json: Mapped[str | None] = mapped_column(
        Text, default="[]", nullable=True
    )


class ExploitCVERecord(Base):
    __tablename__ = "exploit_cves"

    edb_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)


class ProjectRecord(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    notes: Mapped[str | None] = mapped_column(Text, default="", nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime, default=utcnow, nullable=True
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow, nullable=True
    )


class ProjectItemRecord(Base):
    __tablename__ = "project_items"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    # cve | exploit | dork | report | search
    kind: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    ref_id: Mapped[str] = mapped_column(String(128), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, default="", nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime, default=utcnow, nullable=True
    )


class DorkSavedRecord(Base):
    __tablename__ = "dork_saved"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    template_id: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    target_domain: Mapped[str | None] = mapped_column(
        String(256), default="", nullable=True
    )
    username: Mapped[str | None] = mapped_column(String(128), default="", nullable=True)
    query: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str | None] = mapped_column(
        String(16), default="low", nullable=True
    )
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime, default=utcnow, nullable=True
    )


class GeneratedReportRecord(Base):
    __tablename__ = "generated_reports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    project_id: Mapped[str | None] = mapped_column(
        String(64), index=True, nullable=True
    )
    cve_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    edb_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    module_type: Mapped[str | None] = mapped_column(
        String(32), default="", nullable=True
    )
    formats_json: Mapped[str | None] = mapped_column(Text, default="[]", nullable=True)
    paths_json: Mapped[str | None] = mapped_column(Text, default="[]", nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime, default=utcnow, nullable=True
    )


class SavedSearchRecord(Base):
    __tablename__ = "saved_searches"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)  # cve | exploit
    params_json: Mapped[str | None] = mapped_column(Text, default="{}", nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime, default=utcnow, nullable=True
    )


class UserSettingRecord(Base):
    __tablename__ = "user_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value_json: Mapped[str | None] = mapped_column(Text, default="null", nullable=True)


class AuditLogRecord(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime | None] = mapped_column(
        DateTime, default=utcnow, index=True, nullable=True
    )
    event: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    object_kind: Mapped[str | None] = mapped_column(
        String(32), default="", nullable=True
    )
    object_id: Mapped[str | None] = mapped_column(
        String(128), default="", nullable=True
    )
    risk_level: Mapped[str | None] = mapped_column(
        String(16), default="", nullable=True
    )
    details_json: Mapped[str | None] = mapped_column(Text, default="{}", nullable=True)


class SourceStateRecord(Base):
    __tablename__ = "source_state"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_success: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_attempt: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    etag: Mapped[str | None] = mapped_column(String(256), default="", nullable=True)
    last_modified: Mapped[str | None] = mapped_column(
        String(64), default="", nullable=True
    )
    status: Mapped[str | None] = mapped_column(
        String(16), default="never", nullable=True
    )
    error: Mapped[str | None] = mapped_column(Text, default="", nullable=True)
    row_count: Mapped[int | None] = mapped_column(Integer, default=0, nullable=True)


class MetricRecord(Base):
    __tablename__ = "metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime | None] = mapped_column(
        DateTime, default=utcnow, index=True, nullable=True
    )
    name: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    value: Mapped[float | None] = mapped_column(Float, default=0.0, nullable=True)
    tags_json: Mapped[str | None] = mapped_column(Text, default="{}", nullable=True)


class SchemaVersionRecord(Base):
    __tablename__ = "schema_version"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    applied_at: Mapped[datetime | None] = mapped_column(
        DateTime, default=utcnow, nullable=True
    )


_engine = None
_session_factory = None
_db_url: str | None = None

LEGACY_DB_PATH = Path(__file__).resolve().parent / "cveli.db"


def get_database_path() -> str:
    from config.settings import get_settings

    return str(get_settings().db_path)


def _migrate_legacy_location(target: Path) -> None:
    """Copy a pre-2.0 in-package database to the new data dir (once)."""
    if target.exists() or not LEGACY_DB_PATH.exists() or target == LEGACY_DB_PATH:
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(LEGACY_DB_PATH, target)


def _sqlite_file(db_url: str) -> Path | None:
    prefix = "sqlite:///"
    if not db_url.startswith(prefix) or ":memory:" in db_url:
        return None
    return Path(db_url[len(prefix) :])


def init_database(db_url: str | None = None):
    global _engine, _session_factory, _db_url
    if db_url is None:
        if _db_url is not None:
            db_url = _db_url
        else:
            target = Path(get_database_path())
            target.parent.mkdir(parents=True, exist_ok=True)
            _migrate_legacy_location(target)
            db_url = f"sqlite:///{target}"
    if _engine is None or db_url != _db_url:
        if _engine is not None:
            _engine.dispose()
        engine = create_engine(
            db_url, connect_args={"check_same_thread": False}, pool_pre_ping=True
        )

        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn, _record):  # pragma: no cover - trivial
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

        from storage.migrations import migrate

        migrate(engine, _sqlite_file(db_url))
        _engine = engine
        _session_factory = sessionmaker(
            bind=_engine, autocommit=False, autoflush=False, expire_on_commit=False
        )
        _db_url = db_url
    return _session_factory


def get_engine():
    init_database()
    return _engine


def reset_database_state() -> None:
    """Forget the active engine (tests)."""
    global _engine, _session_factory, _db_url
    if _engine is not None:
        _engine.dispose()
    _engine = _session_factory = _db_url = None


@contextmanager
def get_session() -> Generator[Session, None, None]:
    session = init_database()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


create_session = get_session


def _parse_date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00").split(".")[0])
    except ValueError:
        return None
    return parsed.replace(tzinfo=None)


def _fmt(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d") if value else ""


def map_model_to_record(cve: CVEModel) -> CVERecord:
    return CVERecord(
        id=cve.id,
        summary=cve.summary,
        severity=cve.severity,
        cvss_score=cve.cvss,
        vector=cve.vector,
        published_date=_parse_date(cve.published),
        updated_date=_parse_date(cve.updated),
        kev_date=_parse_date(cve.kev_date),
        exploit_available=cve.exploit_available,
        kev=cve.kev,
        public_exploit_count=cve.public_exploit_count,
        epss_score=cve.epss,
        epss_percentile=cve.epss_percentile,
        vendor=cve.vendor,
        cwe_id=f"CWE-{cve.cwe.id}" if cve.cwe else None,
        cwe_name=cve.cwe.name if cve.cwe else None,
        tags_json=json.dumps(cve.tags),
        references_json=json.dumps(cve.references),
        reference_details_json=json.dumps(
            [ref.model_dump() for ref in cve.reference_details]
        ),
        affected_products_json=json.dumps(cve.affected_products),
        sources_json=json.dumps(cve.sources),
        fetched_at=_parse_date(cve.fetched_at) or utcnow(),
    )


def map_record_to_model(rec: CVERecord) -> CVEModel:
    cwe = None
    if rec.cwe_id and rec.cwe_id.startswith("CWE-"):
        try:
            cwe = CWEID(
                id=int(rec.cwe_id.split("-", 1)[1]), name=rec.cwe_name or rec.cwe_id
            )
        except ValueError:
            cwe = None
    sources = json.loads(rec.sources_json or "[]")
    cvss = float(rec.cvss_score) if rec.cvss_score is not None else None
    severity = rec.severity
    if cvss == 0.0 and not {"NVD", "CVE.org"} & set(sources):
        cvss = None
        severity = None
    return CVEModel(
        id=rec.id,
        summary=rec.summary or "",
        severity=severity,
        cvss=cvss,
        vector=rec.vector,
        published=_fmt(rec.published_date),
        updated=_fmt(rec.updated_date),
        kev_date=_fmt(rec.kev_date),
        affected_products=json.loads(rec.affected_products_json or "[]"),
        references=json.loads(rec.references_json or "[]"),
        reference_details=[
            Reference(**ref) for ref in json.loads(rec.reference_details_json or "[]")
        ],
        exploit_available=bool(rec.exploit_available),
        kev=bool(rec.kev),
        public_exploit_count=int(rec.public_exploit_count or 0),
        epss=float(rec.epss_score)
        if "FIRST EPSS" in sources and rec.epss_score is not None
        else None,
        epss_percentile=float(rec.epss_percentile)
        if rec.epss_percentile is not None
        else None,
        vendor=rec.vendor,
        cwe=cwe,
        tags=json.loads(rec.tags_json or "[]"),
        sources=sources,
        fetched_at=_fmt(rec.fetched_at),
    )
