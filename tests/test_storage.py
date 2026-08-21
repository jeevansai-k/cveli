"""
Unit Tests for Storage Layer.

Purpose: Test SQLite database persistence, CVERepository, and WatchlistRepository.
Dependencies: pytest, storage modules.
"""

import pytest

from core.models import CVEModel
from storage.database import init_database
from storage.repositories import CVERepository, WatchlistRepository


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    db_file = tmp_path / "test_cveli.db"
    db_url = f"sqlite:///{db_file}"
    init_database(db_url=db_url)


def test_repository_save_and_get():
    repo = CVERepository()
    model = CVEModel(
        id="CVE-2024-99999",
        summary="Test repository vulnerability",
        severity="Critical",
        cvss=9.8,
        vendor="TestCorp",
    )

    saved = repo.save(model)
    assert saved.id == "CVE-2024-99999"

    fetched = repo.get_by_id("CVE-2024-99999")
    assert fetched is not None
    assert fetched.summary == "Test repository vulnerability"
    assert fetched.cvss == 9.8


def test_repository_persists_kev_date():
    repo = CVERepository()
    repo.save(CVEModel(id="CVE-2024-12340", summary="KEV", kev_date="2024-08-10"))
    fetched = repo.get_by_id("CVE-2024-12340")
    assert fetched is not None
    assert fetched.kev_date == "2024-08-10"


def test_repository_search():
    repo = CVERepository()
    cves = [
        CVEModel(
            id="CVE-2024-10001",
            summary="OpenSSL buffer overflow",
            severity="Critical",
            cvss=9.8,
            vendor="OpenSSL",
        ),
        CVEModel(
            id="CVE-2024-10002",
            summary="Apache HTTPD XSS",
            severity="Medium",
            cvss=6.1,
            vendor="Apache",
        ),
    ]
    repo.save_bulk(cves)

    results = repo.search(query="OpenSSL")
    assert len(results) == 1
    assert results[0].id == "CVE-2024-10001"

    results_sev = repo.search(severity="Medium")
    assert len(results_sev) == 1
    assert results_sev[0].id == "CVE-2024-10002"


def test_watchlist_repository():
    w_repo = WatchlistRepository()
    item = w_repo.add(
        target_type="vendor", target_value="OpenSSL", notes="Track OpenSSL advisories"
    )
    assert item["target_value"] == "OpenSSL"

    items = w_repo.list_all()
    assert len(items) >= 1

    removed = w_repo.remove(item["id"])
    assert removed is True
