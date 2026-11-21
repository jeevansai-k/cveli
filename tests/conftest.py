"""Shared pytest fixtures: isolate every test from the user's real data/config."""

import os
import tempfile
from pathlib import Path

_SESSION_DIR = Path(tempfile.mkdtemp(prefix="cveli-tests-"))
os.environ["CVELI_DISABLE_DOTENV"] = "1"
os.environ["CVELI_DATA_DIR"] = str(_SESSION_DIR / "data")
os.environ["CVELI_CACHE_DIR"] = str(_SESSION_DIR / "cache")
os.environ["CVELI_CONFIG_DIR"] = str(_SESSION_DIR / "config")
os.environ.pop("NVD_API_KEY", None)
os.environ.pop("CVELI_THEME", None)
os.environ.pop("CVELI_DB_PATH", None)
os.environ["TEXTUAL_ANIMATIONS"] = "none"

import pytest  # noqa: E402

from config.settings import reset_settings  # noqa: E402
from utils.http import reset_limiters  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("CVELI_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("CVELI_CACHE_DIR", str(tmp_path / "cache"))
    reset_settings()
    reset_limiters()
    from storage.database import init_database

    init_database(db_url=f"sqlite:///{tmp_path / 'default.db'}")
    yield
    reset_settings()


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def no_sleep(monkeypatch):
    """Make HTTP retries/backoff instant."""
    calls: list[float] = []
    monkeypatch.setattr("utils.http.time.sleep", lambda s: calls.append(s))
    return calls
