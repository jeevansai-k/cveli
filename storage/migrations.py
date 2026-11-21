"""
Versioned database migrations.

Purpose: Bring any CVELI database (fresh, 0.1.x, or partially migrated) to the
current schema. Every migration is idempotent. Before upgrading an existing
on-disk database, a timestamped backup ``<db>.bak-<UTC timestamp>`` is written.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection, Engine

from utils.logger import get_logger

log = get_logger(__name__)


def _columns(conn: Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}


def _add_columns(conn: Connection, table: str, columns: dict[str, str]) -> None:
    existing = _columns(conn, table)
    for name, ddl in columns.items():
        if name not in existing:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


def m001_legacy_columns(conn: Connection) -> None:
    """0.1.x columns that were added ad hoc by ``_ensure_columns``."""
    _add_columns(
        conn,
        "cves",
        {
            "epss_percentile": "FLOAT",
            "sources_json": "TEXT DEFAULT '[]'",
            "fetched_at": "DATETIME",
        },
    )


def m002_v2_cve_columns(conn: Connection) -> None:
    _add_columns(
        conn,
        "cves",
        {
            "kev": "BOOLEAN DEFAULT 0",
            "public_exploit_count": "INTEGER DEFAULT 0",
            "reference_details_json": "TEXT DEFAULT '[]'",
        },
    )
    _add_columns(conn, "watchlists", {"last_checked_at": "DATETIME"})
    conn.execute(
        text(
            "UPDATE cves SET kev = 1 WHERE kev IS NOT 1 AND "
            "exploit_available = 1 AND tags_json LIKE '%cisa_kev%'"
        )
    )
    conn.execute(text("UPDATE cves SET kev = 0 WHERE kev IS NULL"))
    conn.execute(
        text(
            "UPDATE cves SET public_exploit_count = 0 "
            "WHERE public_exploit_count IS NULL"
        )
    )
    # 0.1.x stored "Info" as the default severity for KEV-only rows.
    conn.execute(
        text(
            "UPDATE cves SET severity = NULL "
            "WHERE severity = 'Info' AND cvss_score IS NULL"
        )
    )


def fts5_available(conn: Connection) -> bool:
    try:
        conn.execute(
            text("CREATE VIRTUAL TABLE IF NOT EXISTS _fts5_probe USING fts5(x)")
        )
        conn.execute(text("DROP TABLE IF EXISTS _fts5_probe"))
        return True
    except Exception:
        return False


def m003_exploit_fts(conn: Connection) -> None:
    if not fts5_available(conn):
        log.warning("SQLite FTS5 unavailable; Exploit-DB search uses LIKE fallback.")
        return
    conn.execute(
        text(
            "CREATE VIRTUAL TABLE IF NOT EXISTS exploits_fts USING fts5("
            "title, author, platform, type, tags_json, affected_product, "
            "content='exploits', content_rowid='edb_id', tokenize='unicode61')"
        )
    )


def m004_first_seen(conn: Connection) -> None:
    _add_columns(conn, "cves", {"first_seen_at": "DATETIME"})
    conn.execute(
        text("UPDATE cves SET first_seen_at = fetched_at WHERE first_seen_at IS NULL")
    )


MIGRATIONS: list[tuple[int, str, Callable[[Connection], None]]] = [
    (1, "legacy columns", m001_legacy_columns),
    (2, "2.0 cve columns", m002_v2_cve_columns),
    (3, "exploit full-text index", m003_exploit_fts),
    (4, "cve first-seen timestamp", m004_first_seen),
]
LATEST_VERSION = MIGRATIONS[-1][0]


def current_version(conn: Connection) -> int:
    tables = set(inspect(conn).get_table_names())
    if "schema_version" not in tables:
        return 0
    row = conn.execute(text("SELECT MAX(version) FROM schema_version")).scalar()
    return int(row or 0)


def backup_database(db_file: Path) -> Path | None:
    if not db_file.exists() or db_file.stat().st_size == 0:
        return None
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = db_file.with_name(f"{db_file.name}.bak-{stamp}")
    shutil.copy2(db_file, backup)
    log.info(f"Database backup written to {backup}")
    return backup


def migrate(engine: Engine, db_file: Path | None = None) -> int:
    """Create tables and apply pending migrations. Returns the final version."""
    from storage.database import Base

    with engine.connect() as conn:
        tables = set(inspect(conn).get_table_names())
        version = current_version(conn)
    pending = [item for item in MIGRATIONS if item[0] > version]
    if pending and db_file is not None and "cves" in tables:
        backup_database(db_file)

    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        for number, name, func in pending:
            func(conn)
            conn.execute(
                text(
                    "INSERT INTO schema_version (version, applied_at) VALUES (:v, :ts)"
                ),
                {"v": number, "ts": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")},
            )
            log.info(f"Applied migration {number}: {name}")
        return current_version(conn)


def run_migrations(db_url: str | None = None) -> bool:
    """Initialize the database and apply migrations (CLI helper)."""
    from storage.database import init_database

    try:
        init_database(db_url=db_url)
        return True
    except Exception as error:
        log.error(f"Failed to initialize database: {error}")
        return False


if __name__ == "__main__":
    run_migrations()
