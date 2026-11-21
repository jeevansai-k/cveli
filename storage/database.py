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
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from core.models import CWEID, CVEModel, Reference

Base = declarative_base()


def _uuid() -> str:
    return uuid.uuid4().hex


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class CVERecord(Base):
    __tablename__ = "cves"

    id = Column(String(64), primary_key=True)
    summary = Column(Text, nullable=False, default="")
    severity = Column(String(20), index=True, nullable=True)
    cvss_score = Column(Float, index=True, nullable=True)
    vector = Column(String(128), nullable=True)
    published_date = Column(DateTime, index=True, nullable=True)
    updated_date = Column(DateTime, index=True, nullable=True)
    kev_date = Column(DateTime, index=True, nullable=True)
    exploit_available = Column(Boolean, default=False, index=True)
    kev = Column(Boolean, default=False, index=True)
    public_exploit_count = Column(Integer, default=0, index=True)
    epss_score = Column(Float, index=True, nullable=True)
    epss_percentile = Column(Float, index=True, nullable=True)
    vendor = Column(String(128), index=True, nullable=True)
    cwe_id = Column(String(32), index=True, nullable=True)
    cwe_name = Column(String(256), nullable=True)
    tags_json = Column(Text, default="[]")
    references_json = Column(Text, default="[]")
    reference_details_json = Column(Text, default="[]")
    affected_products_json = Column(Text, default="[]")
    sources_json = Column(Text, default="[]")
    fetched_at = Column(DateTime, index=True, nullable=True)


class WatchlistItemRecord(Base):
    __tablename__ = "watchlists"

    id = Column(String(64), primary_key=True, default=_uuid)
    target_type = Column(String(32), index=True, nullable=False)
    target_value = Column(String(256), index=True, nullable=False)
    created_at = Column(DateTime, default=utcnow)
    notes = Column(Text, default="")
    last_checked_at = Column(DateTime, nullable=True)


class ExploitRecord(Base):
    __tablename__ = "exploits"

    edb_id = Column(Integer, primary_key=True, autoincrement=False)
    title = Column(Text, nullable=False, default="")
    description = Column(Text, nullable=True)
    author = Column(String(256), index=True, default="")
    platform = Column(String(64), index=True, default="")
    type = Column(String(32), index=True, default="")
    port = Column(Integer, nullable=True)
    date_published = Column(String(10), index=True, default="")
    date_added = Column(String(10), default="")
    date_updated = Column(String(10), default="")
    verified = Column(Boolean, index=True, default=False)
    file_path = Column(String(512), default="")
    advisory_url = Column(Text, default="")
    tags_json = Column(Text, default="[]")
    aliases_json = Column(Text, default="[]")
    cve_ids_json = Column(Text, default="[]")
    affected_product = Column(String(256), index=True, nullable=True)
    affected_versions_json = Column(Text, default="[]")


class ExploitCVERecord(Base):
    __tablename__ = "exploit_cves"

    edb_id = Column(Integer, primary_key=True)
    cve_id = Column(String(64), primary_key=True, index=True)


class ProjectRecord(Base):
    __tablename__ = "projects"

    id = Column(String(64), primary_key=True, default=_uuid)
    name = Column(String(256), nullable=False, unique=True)
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class ProjectItemRecord(Base):
    __tablename__ = "project_items"

    id = Column(String(64), primary_key=True, default=_uuid)
    project_id = Column(String(64), index=True, nullable=False)
    kind = Column(String(32), index=True, nullable=False)  # cve|exploit|dork|report
    ref_id = Column(String(128), nullable=False)
    note = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow)


class DorkSavedRecord(Base):
    __tablename__ = "dork_saved"

    id = Column(String(64), primary_key=True, default=_uuid)
    project_id = Column(String(64), index=True, nullable=False)
    template_id = Column(String(64), nullable=False)
    category = Column(String(32), nullable=False)
    target_domain = Column(String(256), default="")
    username = Column(String(128), default="")
    query = Column(Text, nullable=False)
    risk_level = Column(String(16), default="low")
    created_at = Column(DateTime, default=utcnow)


class GeneratedReportRecord(Base):
    __tablename__ = "generated_reports"

    id = Column(String(64), primary_key=True, default=_uuid)
    project_id = Column(String(64), index=True, nullable=True)
    cve_id = Column(String(64), index=True, nullable=True)
    edb_id = Column(Integer, index=True, nullable=True)
    module_type = Column(String(32), default="")
    formats_json = Column(Text, default="[]")
    paths_json = Column(Text, default="[]")
    created_at = Column(DateTime, default=utcnow)


class SavedSearchRecord(Base):
    __tablename__ = "saved_searches"

    id = Column(String(64), primary_key=True, default=_uuid)
    name = Column(String(128), nullable=False, unique=True)
    kind = Column(String(16), nullable=False)  # cve|exploit
    params_json = Column(Text, default="{}")
    created_at = Column(DateTime, default=utcnow)


class UserSettingRecord(Base):
    __tablename__ = "user_settings"

    key = Column(String(64), primary_key=True)
    value_json = Column(Text, default="null")


class AuditLogRecord(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, default=utcnow, index=True)
    event = Column(String(64), index=True, nullable=False)
    object_kind = Column(String(32), default="")
    object_id = Column(String(128), default="")
    risk_level = Column(String(16), default="")
    details_json = Column(Text, default="{}")


class SourceStateRecord(Base):
    __tablename__ = "source_state"

    source = Column(String(32), primary_key=True)
    last_success = Column(DateTime, nullable=True)
    last_attempt = Column(DateTime, nullable=True)
    etag = Column(String(256), default="")
    last_modified = Column(String(64), default="")
    status = Column(String(16), default="never")
    error = Column(Text, default="")
    row_count = Column(Integer, default=0)


class MetricRecord(Base):
    __tablename__ = "metrics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, default=utcnow, index=True)
    name = Column(String(64), index=True, nullable=False)
    value = Column(Float, default=0.0)
    tags_json = Column(Text, default="{}")


class SchemaVersionRecord(Base):
    __tablename__ = "schema_version"

    id = Column(Integer, primary_key=True)
    version = Column(Integer, nullable=False, default=0)
    applied_at = Column(DateTime, default=utcnow)


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
