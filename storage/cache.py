"""
Disk Cache Layer.

Purpose: Provide local disk-based key-value caching using diskcache.
Inputs: Cache keys, data values, TTL seconds.
Outputs: Cached objects or None on miss.
Responsibilities: Store HTTP responses and query results locally.
Dependencies: diskcache, config.settings.
"""

from pathlib import Path
from typing import Any

import diskcache

_cache = None


def get_cache_directory() -> str:
    """Return cache directory path."""
    project_root = Path(__file__).resolve().parent.parent
    cache_dir = project_root / "storage" / ".cache"
    return str(cache_dir)


def get_cache() -> diskcache.Cache:
    """Get global Cache instance."""
    global _cache
    if _cache is None:
        cache_dir = get_cache_directory()
        _cache = diskcache.Cache(cache_dir)
    return _cache


def cache_get(key: str, default: Any = None) -> Any:
    """Get value from cache."""
    try:
        cache = get_cache()
        return cache.get(key, default=default)
    except Exception:
        return default


def cache_set(key: str, value: Any, expire: int | None = 3600) -> bool:
    """Set value in cache with optional expiration in seconds."""
    try:
        cache = get_cache()
        cache.set(key, value, expire=expire)
        return True
    except Exception:
        return False


def cache_clear() -> bool:
    """Clear all cached entries."""
    try:
        cache = get_cache()
        cache.clear()
        return True
    except Exception:
        return False
