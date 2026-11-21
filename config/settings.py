"""
Typed application settings.

Purpose: Load configuration from the environment (and an optional ``.env`` file)
into a single immutable ``Settings`` object.
Inputs: Environment variables, ``.env`` in the working directory or
``$XDG_CONFIG_HOME/cveli/.env``.
Outputs: ``Settings`` via ``get_settings()``.

Precedence: real environment > ``.env`` (dotenv never overrides set variables)
> built-in defaults. Set ``CVELI_DISABLE_DOTENV=1`` to skip ``.env`` loading.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from config.defaults import DEFAULT_SETTINGS

TRUE_VALUES = {"1", "true", "yes", "on"}


def _env(key: str, default: str = "") -> str:
    value = os.environ.get(key)
    if value is None:
        return default
    # Strip inline comments such as "1440  # daily" from copied .env examples.
    return value.split(" #", 1)[0].strip()


def _env_bool(key: str, default: bool) -> bool:
    raw = _env(key)
    if not raw:
        return default
    return raw.lower() in TRUE_VALUES


def _env_int(key: str, default: int) -> int:
    raw = _env(key)
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _env_float(key: str, default: float) -> float:
    raw = _env(key)
    try:
        return float(raw) if raw else default
    except ValueError:
        return default


def _xdg(var: str, fallback: str) -> Path:
    base = os.environ.get(var)
    return Path(base).expanduser() if base else Path.home() / fallback


def _path(key: str, default: Path) -> Path:
    raw = _env(key)
    return Path(raw).expanduser().resolve() if raw else default


def config_dir() -> Path:
    return _path("CVELI_CONFIG_DIR", _xdg("XDG_CONFIG_HOME", ".config") / "cveli")


def load_dotenv_files() -> list[Path]:
    """Load ``.env`` files without overriding the real environment."""
    if _env_bool("CVELI_DISABLE_DOTENV", False):
        return []
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover - dependency is declared
        return []
    loaded: list[Path] = []
    for candidate in (Path.cwd() / ".env", config_dir() / ".env"):
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            loaded.append(candidate)
    return loaded


@dataclass(frozen=True)
class Settings:
    nvd_api_key: str = ""
    cve_org_api_key: str = ""
    data_dir: Path = field(default_factory=Path)
    db_path: Path = field(default_factory=Path)
    cache_dir: Path = field(default_factory=Path)
    log_dir: Path = field(default_factory=Path)
    config_dir: Path = field(default_factory=Path)
    log_level: str = "INFO"
    http_timeout: float = 30.0
    http_retries: int = 3
    cache_size_limit_mb: int = 256
    search_cache_ttl: int = 3600
    kev_ttl_hours: int = 24
    epss_batch_size: int = 100
    exploitdb_url: str = DEFAULT_SETTINGS["exploitdb_url"]
    exploitdb_path: str = ""
    exploitdb_ttl_hours: int = 24
    feature_exploitdb: bool = True
    feature_dorks: bool = True
    feature_msf: bool = True
    metrics_enabled: bool = True
    metrics_retention_days: int = 30
    audit_retention_days: int = 90
    dork_open_min_interval: float = 5.0
    dork_open_per_hour: int = 30
    theme: str = ""
    reduce_motion: bool = False
    loaded_env_files: tuple[str, ...] = ()

    @property
    def db_url(self) -> str:
        return f"sqlite:///{self.db_path}"

    @property
    def nvd_rate(self) -> tuple[int, float]:
        """NVD public limits: 5 req / 30 s anonymous, 50 req / 30 s with a key."""
        return (50, 30.0) if self.nvd_api_key else (5, 30.0)

    def redacted(self) -> dict[str, str]:
        """Settings safe to print (secrets masked)."""
        out: dict[str, str] = {}
        for key, value in self.__dict__.items():
            if key.endswith("api_key"):
                out[key] = "set" if value else "not set"
            else:
                out[key] = str(value)
        return out


def build_settings() -> Settings:
    loaded = load_dotenv_files()
    data_dir = _path("CVELI_DATA_DIR", _xdg("XDG_DATA_HOME", ".local/share") / "cveli")
    cache_dir = _path("CVELI_CACHE_DIR", _xdg("XDG_CACHE_HOME", ".cache") / "cveli")
    return Settings(
        nvd_api_key=_env("NVD_API_KEY"),
        cve_org_api_key=_env("CVE_ORG_API_KEY"),
        data_dir=data_dir,
        db_path=_path("CVELI_DB_PATH", data_dir / "cveli.db"),
        cache_dir=cache_dir,
        log_dir=_path("CVELI_LOG_DIR", cache_dir / "logs"),
        config_dir=config_dir(),
        log_level=_env("CVELI_LOG_LEVEL", "INFO").upper(),
        http_timeout=_env_float("CVELI_HTTP_TIMEOUT", 30.0),
        http_retries=_env_int("CVELI_HTTP_RETRIES", 3),
        cache_size_limit_mb=_env_int("CVELI_CACHE_SIZE_MB", 256),
        search_cache_ttl=_env_int("CVELI_SEARCH_CACHE_TTL", 3600),
        kev_ttl_hours=_env_int("CVELI_KEV_TTL_HOURS", 24),
        epss_batch_size=max(1, min(_env_int("CVELI_EPSS_BATCH", 100), 100)),
        exploitdb_url=_env("EXPLOITDB_URL", DEFAULT_SETTINGS["exploitdb_url"]),
        exploitdb_path=_env("EXPLOITDB_PATH"),
        exploitdb_ttl_hours=_env_int("CVELI_EXPLOITDB_TTL_HOURS", 24),
        feature_exploitdb=_env_bool("CVELI_FEATURE_EXPLOITDB", True),
        feature_dorks=_env_bool("CVELI_FEATURE_DORKS", True),
        feature_msf=_env_bool("CVELI_FEATURE_MSF", True),
        metrics_enabled=_env_bool("CVELI_METRICS", True),
        metrics_retention_days=_env_int("CVELI_METRICS_RETENTION_DAYS", 30),
        audit_retention_days=_env_int("CVELI_AUDIT_RETENTION_DAYS", 90),
        dork_open_min_interval=_env_float("CVELI_DORK_OPEN_INTERVAL", 5.0),
        dork_open_per_hour=_env_int("CVELI_DORK_OPEN_PER_HOUR", 30),
        theme=_env("CVELI_THEME").lower(),
        reduce_motion=_env_bool("CVELI_REDUCE_MOTION", False),
        loaded_env_files=tuple(str(path) for path in loaded),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return build_settings()


def reset_settings() -> None:
    """Drop the cached settings (tests / after changing the environment)."""
    get_settings.cache_clear()


def get_setting(key: str, default_value=None):
    """Backward-compatible accessor used by older code paths."""
    settings = get_settings()
    attr = key.lower()
    if hasattr(settings, attr):
        return getattr(settings, attr)
    return os.environ.get(key.upper(), DEFAULT_SETTINGS.get(attr, default_value))
