"""
Database Migrations.

Purpose: Initialize database schema and handle simple schema migrations.
Inputs: Engine or database path.
Outputs: Schema initialization status.
Responsibilities: Ensure tables exist and database version tracking.
Dependencies: storage.database.
"""

from storage.database import init_database
from utils.logger import get_logger

log = get_logger(__name__)


def run_migrations(db_url: str = None) -> bool:
    """Run database table creation and schema migration checks."""
    try:
        init_database(db_url=db_url)
        log.info("Database initialized successfully.")
        return True
    except Exception as e:
        log.error(f"Failed to initialize database: {e}")
        return False


if __name__ == "__main__":
    run_migrations()
