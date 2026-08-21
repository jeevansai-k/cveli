import json
import os
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
    String,
    Text,
    create_engine,
    text,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from core.models import CWEID, CVEModel

Base = declarative_base()


class CVERecord(Base):
    __tablename__ = "cves"

    id = Column(String(64), primary_key=True)
    summary = Column(Text, nullable=False, default="")
    severity = Column(String(20), index=True, default="Info")
    cvss_score = Column(Float, index=True, nullable=True)
    vector = Column(String(128), nullable=True)
    published_date = Column(DateTime, index=True, nullable=True)
    updated_date = Column(DateTime, index=True, nullable=True)
    kev_date = Column(DateTime, index=True, nullable=True)
    exploit_available = Column(Boolean, default=False, index=True)
    epss_score = Column(Float, index=True, nullable=True)
    epss_percentile = Column(Float, index=True, nullable=True)
    vendor = Column(String(128), index=True, nullable=True)
    cwe_id = Column(String(32), index=True, nullable=True)
    cwe_name = Column(String(256), nullable=True)
    tags_json = Column(Text, default="[]")
    references_json = Column(Text, default="[]")
    affected_products_json = Column(Text, default="[]")
    sources_json = Column(Text, default="[]")
    fetched_at = Column(DateTime, index=True, nullable=True)


class WatchlistItemRecord(Base):
    __tablename__ = "watchlists"

    id = Column(String(64), primary_key=True, default=lambda: uuid.uuid4().hex)
    target_type = Column(String(32), index=True, nullable=False)
    target_value = Column(String(256), index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    notes = Column(Text, default="")


_engine = None
_session_factory = None
_db_url = None


def get_database_path() -> str:
    return str(Path(__file__).resolve().parent / "cveli.db")


def init_database(db_url: str | None = None):
    global _engine, _session_factory, _db_url
    if db_url is None:
        if _db_url is not None:
            db_url = _db_url
        else:
            db_path = get_database_path()
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            db_url = f"sqlite:///{db_path}"
    if _engine is None or db_url != _db_url:
        if _engine is not None:
            _engine.dispose()
        _engine = create_engine(
            db_url, connect_args={"check_same_thread": False}, pool_pre_ping=True
        )
        _session_factory = sessionmaker(
            bind=_engine, autocommit=False, autoflush=False, expire_on_commit=False
        )
        _db_url = db_url
        Base.metadata.create_all(bind=_engine)
        _ensure_columns(_engine)
    return _session_factory


def _ensure_columns(engine) -> None:
    with engine.begin() as conn:
        existing = {row[1] for row in conn.execute(text("PRAGMA table_info(cves)"))}
        for name, ddl in {
            "epss_percentile": "FLOAT",
            "sources_json": "TEXT DEFAULT '[]'",
            "fetched_at": "DATETIME",
        }.items():
            if name not in existing:
                conn.execute(text(f"ALTER TABLE cves ADD COLUMN {name} {ddl}"))


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


def _parse_date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00").split(".")[0])
    except ValueError:
        return None


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
        epss_score=cve.epss,
        epss_percentile=cve.epss_percentile,
        vendor=cve.vendor,
        cwe_id=f"CWE-{cve.cwe.id}" if cve.cwe else None,
        cwe_name=cve.cwe.name if cve.cwe else None,
        tags_json=json.dumps(cve.tags),
        references_json=json.dumps(cve.references),
        affected_products_json=json.dumps(cve.affected_products),
        sources_json=json.dumps(cve.sources),
        fetched_at=_parse_date(cve.fetched_at) or datetime.now(UTC),
    )


def map_record_to_model(rec: CVERecord) -> CVEModel:
    cwe = None
    if rec.cwe_id and rec.cwe_id.startswith("CWE-"):
        cwe = CWEID(
            id=int(rec.cwe_id.split("-", 1)[1]), name=rec.cwe_name or rec.cwe_id
        )
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
        published=rec.published_date.strftime("%Y-%m-%d") if rec.published_date else "",
        updated=rec.updated_date.strftime("%Y-%m-%d") if rec.updated_date else "",
        kev_date=rec.kev_date.strftime("%Y-%m-%d") if rec.kev_date else "",
        affected_products=json.loads(rec.affected_products_json or "[]"),
        references=json.loads(rec.references_json or "[]"),
        exploit_available=bool(rec.exploit_available),
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
        fetched_at=rec.fetched_at.strftime("%Y-%m-%d") if rec.fetched_at else "",
    )
