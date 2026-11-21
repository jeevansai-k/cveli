"""Phase 0 foundations: settings, HTTP client, migrations, theme tokens, logging."""

import os
import re
import sqlite3
from pathlib import Path

import httpx
import pytest

from cli.tui.theme import (
    DARK,
    LIGHT,
    PALETTES,
    detect_system_theme,
    resolve_theme_name,
)
from config.settings import get_settings, reset_settings
from storage.database import init_database, reset_database_state
from storage.migrations import LATEST_VERSION
from utils.color import contrast_ratio
from utils.errors import NetworkError
from utils.http import HttpClient, RateLimiter, parse_retry_after
from utils.logger import REDACTED, redact, sensitive

ROOT = Path(__file__).resolve().parent.parent


# --- settings ---------------------------------------------------------------


def test_settings_read_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("NVD_API_KEY", "abc123")
    monkeypatch.setenv("CVELI_DB_PATH", str(tmp_path / "x.db"))
    monkeypatch.setenv("CVELI_FEATURE_DORKS", "0")
    monkeypatch.setenv("SYNC_INTERVAL_MINUTES", "1440  # daily")
    reset_settings()
    settings = get_settings()
    assert settings.nvd_api_key == "abc123"
    assert settings.db_path == (tmp_path / "x.db").resolve()
    assert settings.feature_dorks is False
    assert settings.nvd_rate == (50, 30.0)
    assert settings.redacted()["nvd_api_key"] == "set"


def test_settings_load_dotenv_without_overriding(monkeypatch, tmp_path):
    (tmp_path / ".env").write_text("NVD_API_KEY=from-dotenv\nCVELI_LOG_LEVEL=debug\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CVELI_DISABLE_DOTENV", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setenv("CVELI_LOG_LEVEL", "WARNING")
    reset_settings()
    settings = get_settings()
    assert settings.nvd_api_key == "from-dotenv"
    assert settings.log_level == "WARNING"
    os.environ.pop("NVD_API_KEY", None)


def test_settings_anonymous_nvd_rate():
    assert get_settings().nvd_rate == (5, 30.0)


def test_config_defaults_importable():
    import config.defaults as defaults

    assert defaults.DEFAULT_SETTINGS["version"] == "2.0.0"


def test_single_version_source():
    from config.version import __version__

    offenders = []
    for path in ROOT.glob("*/**/*.py"):
        if ".venv" in path.parts or path.name == "version.py":
            continue
        if re.search(r"\b0\.1\.0\b", path.read_text(encoding="utf-8")):
            offenders.append(str(path))
    assert __version__ == "2.0.0"
    assert offenders == []


# --- http -------------------------------------------------------------------


def test_rate_limiter_token_bucket():
    now = [0.0]
    limiter = RateLimiter(2, 10.0, clock=lambda: now[0], sleep=lambda s: None)
    assert limiter.try_acquire()
    assert limiter.try_acquire()
    assert not limiter.try_acquire()
    assert limiter.wait_time() == pytest.approx(5.0)
    now[0] = 5.0
    assert limiter.try_acquire()


def test_parse_retry_after():
    assert parse_retry_after("7") == 7.0
    assert parse_retry_after(None) is None
    assert parse_retry_after("garbage") is None
    assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT", now=0) > 0


def test_http_retries_on_429_then_succeeds(httpx_mock, no_sleep):
    url = "https://example.org/api"
    httpx_mock.add_response(url=url, status_code=429, headers={"Retry-After": "2"})
    httpx_mock.add_response(url=url, status_code=200, text="ok")
    response = HttpClient("Example", retries=2).get(url)
    assert response.text == "ok"
    assert no_sleep == [2.0]


def test_http_gives_up_after_retries(httpx_mock, no_sleep):
    url = "https://example.org/down"
    for _ in range(3):
        httpx_mock.add_response(url=url, status_code=503)
    with pytest.raises(NetworkError) as excinfo:
        HttpClient("Example", retries=2).get(url)
    assert excinfo.value.status == 503


def test_http_network_error_is_retried(httpx_mock, no_sleep):
    url = "https://example.org/flaky"
    httpx_mock.add_exception(httpx.ConnectTimeout("boom"), url=url)
    httpx_mock.add_response(url=url, status_code=200, text="ok")
    assert HttpClient("Example", retries=1).get(url).text == "ok"


def test_http_non_retryable_status_raises_immediately(httpx_mock, no_sleep):
    url = "https://example.org/missing"
    httpx_mock.add_response(url=url, status_code=404)
    with pytest.raises(NetworkError):
        HttpClient("Example", retries=3).get(url)
    assert no_sleep == []


def test_http_sends_versioned_user_agent(httpx_mock):
    httpx_mock.add_response(url="https://example.org/ua", status_code=200)
    HttpClient("Example").get("https://example.org/ua")
    assert "cveli/2.0.0" in httpx_mock.get_requests()[0].headers["User-Agent"]


# --- migrations -------------------------------------------------------------


def _legacy_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE cves (
            id VARCHAR(64) PRIMARY KEY, summary TEXT NOT NULL, severity VARCHAR(20),
            cvss_score FLOAT, vector VARCHAR(128), published_date DATETIME,
            updated_date DATETIME, kev_date DATETIME, exploit_available BOOLEAN,
            epss_score FLOAT, vendor VARCHAR(128), cwe_id VARCHAR(32),
            cwe_name VARCHAR(256), tags_json TEXT, references_json TEXT,
            affected_products_json TEXT
        );
        CREATE TABLE watchlists (
            id VARCHAR(64) PRIMARY KEY, target_type VARCHAR(32) NOT NULL,
            target_value VARCHAR(256) NOT NULL, created_at DATETIME, notes TEXT
        );
        INSERT INTO cves VALUES ('CVE-2020-0001', 'legacy kev', 'Info', NULL, NULL,
            NULL, NULL, '2020-01-02 00:00:00.000000', 1, NULL, 'Acme', NULL, NULL,
            '["cisa_kev"]', '[]', '[]');
        """
    )
    conn.commit()
    conn.close()


def test_migrates_legacy_database_with_backup(tmp_path):
    db_file = tmp_path / "legacy.db"
    _legacy_db(db_file)
    reset_database_state()
    init_database(db_url=f"sqlite:///{db_file}")
    backups = list(tmp_path.glob("legacy.db.bak-*"))
    assert len(backups) == 1

    from storage.repositories import CVERepository

    cve = CVERepository().get_by_id("CVE-2020-0001")
    assert cve is not None
    assert cve.kev is True
    assert cve.severity is None
    assert cve.kev_date == "2020-01-02"

    conn = sqlite3.connect(db_file)
    version = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    conn.close()
    assert version == LATEST_VERSION
    assert {"exploits", "exploit_cves", "audit_log", "projects"} <= tables


def test_migrations_are_idempotent(tmp_path):
    db_file = tmp_path / "fresh.db"
    reset_database_state()
    init_database(db_url=f"sqlite:///{db_file}")
    reset_database_state()
    init_database(db_url=f"sqlite:///{db_file}")
    assert not list(tmp_path.glob("fresh.db.bak-*"))
    conn = sqlite3.connect(db_file)
    rows = conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0]
    conn.close()
    assert rows == LATEST_VERSION


def test_default_database_lives_in_data_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("CVELI_DATA_DIR", str(tmp_path / "xdg"))
    reset_settings()
    reset_database_state()
    init_database()
    assert (tmp_path / "xdg" / "cveli.db").exists()


# --- theme tokens -----------------------------------------------------------


@pytest.mark.parametrize("name", [DARK, LIGHT])
def test_token_contrast_aa(name):
    palette = PALETTES[name]
    failures = []
    for surface_name, surface in palette.surface_tokens().items():
        for token, color in palette.text_tokens().items():
            ratio = contrast_ratio(color, surface)
            if ratio < 4.5:
                failures.append(f"{token} on {surface_name}: {ratio:.2f}")
        if contrast_ratio(palette.focus, surface) < 3.0:
            failures.append(f"focus on {surface_name}")
    assert failures == []


def test_no_hardcoded_colors_outside_theme():
    hex_color = re.compile(r"#[0-9a-fA-F]{6}\b")
    offenders = []
    for folder in ("cli", "core", "services"):
        for path in (ROOT / folder).rglob("*"):
            if path.suffix not in {".py", ".tcss"} or path.name == "theme.py":
                continue
            if hex_color.search(path.read_text(encoding="utf-8")):
                offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []


def test_theme_resolution():
    assert resolve_theme_name("dark") == DARK
    assert resolve_theme_name("light") == LIGHT
    assert detect_system_theme({"COLORFGBG": "0;15"}) == LIGHT
    assert detect_system_theme({"COLORFGBG": "15;0"}) == DARK
    assert detect_system_theme({}) == DARK


# --- logging redaction ------------------------------------------------------


def test_redaction_of_sensitive_inputs_and_secrets():
    with sensitive("alice-handle", "target.example"):
        line = redact("dork for Alice-Handle on target.example apiKey=XYZ")
    assert "alice" not in line.lower()
    assert "target.example" not in line
    assert "XYZ" not in line
    assert line.count(REDACTED) == 3
    assert redact("alice-handle") == "alice-handle"
