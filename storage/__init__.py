"""
Storage Layer.

Purpose: Handle all data persistence and caching operations.
Inputs: Read/write queries, cache keys, file paths.
Outputs: Database records, cached data, exported files.
Responsibilities: SQLite management, disk-based caching, migrations.
Dependencies: sqlalchemy for DB access, diskcache for local caching.

Functions/Classes:
    - database.py: Database connection and schema management
    - repositories.py: CRUD operations on specific data types
    - cache.py: Local disk-based caching of fetched data

Example:
    From sync.py:
        from storage.database import init_database, create_session

        # Connect to DB and run migration
        init_database()
        with create_session() as session:
            # Fetch CVEs into database
"""

# Re-export main functions for convenient imports
from .database import *  # noqa
from .repositories import *  # noqa
from .cache import *  # noqa
