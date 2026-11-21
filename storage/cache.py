"""
Disk Cache Layer.

Purpose: Local disk-based key-value caching (diskcache) for query results and
feed snapshots. Location: ``settings.cache_dir / "diskcache"``; bounded by
``settings.cache_size_limit_mb`` (least-recently-stored entries are culled).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import diskcache

_cache: diskcache.Cache | None = None
_cache_dir: str | None = None


def get_cache_directory() -> str:
    from config.settings import get_settings

    return str(Path(get_settings().cache_dir) / "diskcache")


def get_cache() -> diskcache.Cache:
    """Get the process-wide Cache instance (re-opened if the directory changes)."""
    global _cache, _cache_dir
    from config.settings import get_settings

    directory = get_cache_directory()
    if _cache is None or _cache_dir != directory:
        if _cache is not None:
            _cache.close()
        limit = max(1, get_settings().cache_size_limit_mb) * 1024 * 1024
        _cache = diskcache.Cache(directory, size_limit=limit)
        _cache_dir = directory
    return _cache


def cache_get(key: str, default: Any = None) -> Any:
    try:
        return get_cache().get(key, default=default)
    except Exception:
        return default


def cache_set(key: str, value: Any, expire: int | None = 3600) -> bool:
    try:
        get_cache().set(key, value, expire=expire)
        return True
    except Exception:
        return False


def cache_delete_prefix(prefix: str) -> int:
    removed = 0
    try:
        cache = get_cache()
        for key in list(cache.iterkeys()):
            if isinstance(key, str) and key.startswith(prefix):
                removed += int(cache.delete(key))
    except Exception:
        return removed
    return removed


def cache_clear() -> bool:
    try:
        get_cache().clear()
        return True
    except Exception:
        return False


def cache_stats() -> dict[str, Any]:
    try:
        cache = get_cache()
        return {
            "directory": cache.directory,
            "entries": len(cache),
            "size_bytes": cache.volume(),
            "size_limit_bytes": cache.size_limit,
        }
    except Exception as error:
        return {"error": str(error)}


def cache_cleanup() -> dict[str, int]:
    """Expire stale entries and cull to the size limit."""
    try:
        cache = get_cache()
        return {"expired": cache.expire(), "culled": cache.cull()}
    except Exception:
        return {"expired": 0, "culled": 0}
