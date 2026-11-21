"""
Shared HTTP client.

Purpose: One place for timeouts, retries, backoff, ``Retry-After`` handling and
per-host rate limiting so every source adapter behaves politely.
Outputs: ``httpx.Response`` objects or ``NetworkError``.
"""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable, Iterable
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from config.version import USER_AGENT
from utils.errors import NetworkError
from utils.logger import get_logger

log = get_logger(__name__)

RETRY_STATUSES = {429, 500, 502, 503, 504}
MAX_BACKOFF_SECONDS = 60.0


class RateLimiter:
    """Thread-safe token bucket: ``rate`` requests per ``per`` seconds."""

    def __init__(
        self,
        rate: int,
        per: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.rate = max(1, int(rate))
        self.per = float(per)
        self._clock = clock
        self._sleep = sleep or (lambda seconds: time.sleep(seconds))
        self._tokens = float(self.rate)
        self._updated = clock()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._updated
        self._updated = now
        self._tokens = min(self.rate, self._tokens + elapsed * self.rate / self.per)

    def try_acquire(self) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= 1:
                self._tokens -= 1
                return True
            return False

    def wait_time(self) -> float:
        with self._lock:
            self._refill()
            if self._tokens >= 1:
                return 0.0
            return (1 - self._tokens) * self.per / self.rate

    def acquire(self) -> None:
        while not self.try_acquire():
            self._sleep(max(self.wait_time(), 0.01))


# Conservative defaults; NVD is re-configured from settings (API key aware).
DEFAULT_HOST_LIMITS: dict[str, tuple[int, float]] = {
    "services.nvd.nist.gov": (5, 30.0),
    "cveawg.mitre.org": (30, 60.0),
    "api.first.org": (30, 60.0),
    "www.cisa.gov": (10, 60.0),
    "gitlab.com": (6, 60.0),
}

_limiters: dict[str, RateLimiter] = {}
_limiters_lock = threading.Lock()


def configure_host_limit(host: str, rate: int, per: float) -> None:
    with _limiters_lock:
        _limiters[host] = RateLimiter(rate, per)


def limiter_for(host: str) -> RateLimiter | None:
    with _limiters_lock:
        if host not in _limiters and host in DEFAULT_HOST_LIMITS:
            rate, per = DEFAULT_HOST_LIMITS[host]
            _limiters[host] = RateLimiter(rate, per)
        return _limiters.get(host)


def reset_limiters() -> None:
    with _limiters_lock:
        _limiters.clear()


def parse_retry_after(value: str | None, now: float | None = None) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        target = parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError):
        return None
    return max(0.0, target - (now if now is not None else time.time()))


class HttpClient:
    """Small wrapper around ``httpx.Client`` with retries and rate limiting."""

    def __init__(
        self,
        endpoint: str,
        timeout: float | None = None,
        retries: int | None = None,
        backoff: float = 1.0,
        sleep: Callable[[float], None] | None = None,
        user_agent: str = USER_AGENT,
    ) -> None:
        from config.settings import get_settings

        settings = get_settings()
        self.endpoint = endpoint
        self.timeout = float(timeout if timeout is not None else settings.http_timeout)
        self.retries = int(retries if retries is not None else settings.http_retries)
        self.backoff = backoff
        self._sleep = sleep or (lambda seconds: time.sleep(seconds))
        self.user_agent = user_agent

    def _delay(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return min(retry_after, MAX_BACKOFF_SECONDS)
        base = self.backoff * (2**attempt)
        return min(base + random.uniform(0, self.backoff), MAX_BACKOFF_SECONDS)

    def get(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        ok_statuses: Iterable[int] = (200,),
    ) -> httpx.Response:
        ok = set(ok_statuses)
        merged_headers = {"User-Agent": self.user_agent, **(headers or {})}
        host = urlparse(url).netloc
        last_error: str = ""
        status = 0
        for attempt in range(self.retries + 1):
            limiter = limiter_for(host)
            if limiter:
                limiter.acquire()
            retry_after: float | None = None
            try:
                with httpx.Client(
                    timeout=self.timeout, follow_redirects=True
                ) as client:
                    response = client.get(url, params=params, headers=merged_headers)
            except httpx.HTTPError as error:
                last_error = f"{type(error).__name__}: {error}"
                status = 0
            else:
                status = response.status_code
                if status in ok:
                    return response
                if status not in RETRY_STATUSES:
                    raise NetworkError(
                        endpoint=self.endpoint,
                        status=status,
                        message=f"{self.endpoint} returned HTTP {status}",
                    )
                retry_after = parse_retry_after(response.headers.get("Retry-After"))
                last_error = f"HTTP {status}"
            if attempt < self.retries:
                delay = self._delay(attempt, retry_after)
                log.warning(
                    f"{self.endpoint} request failed ({last_error}); "
                    f"retry {attempt + 1}/{self.retries} in {delay:.1f}s"
                )
                self._sleep(delay)
        raise NetworkError(
            endpoint=self.endpoint,
            status=status,
            message=f"{self.endpoint} request failed after retries: {last_error}",
        )
