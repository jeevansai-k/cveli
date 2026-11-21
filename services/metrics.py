"""
Local-only telemetry.

Records counters/timings (search latency, integration failures, feature use)
in the local SQLite ``metrics`` table. Nothing is ever sent over the network
and no user-entered text is recorded — only metric names and enum-like tags.
Disable with ``CVELI_METRICS=0``.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from config.settings import get_settings

ALLOWED_TAG_KEYS = {"source", "feature", "format", "category", "outcome", "module_type"}


def record_metric(name: str, value: float = 1.0, **tags: Any) -> None:
    if not get_settings().metrics_enabled:
        return
    safe_tags = {k: str(v)[:32] for k, v in tags.items() if k in ALLOWED_TAG_KEYS}
    try:
        from storage.system_repositories import MetricsRepository

        MetricsRepository().record(name, value, **safe_tags)
    except Exception:
        pass


def feature_used(feature: str, **tags: Any) -> None:
    record_metric("feature.used", 1, feature=feature, **tags)


@contextmanager
def timed(name: str, **tags: Any) -> Iterator[None]:
    started = time.monotonic()
    try:
        yield
    finally:
        record_metric(name, (time.monotonic() - started) * 1000, **tags)
