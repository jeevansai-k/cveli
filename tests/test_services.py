"""
Unit Tests for Application Services.

Purpose: Test Sync, Export, Watchlist, and Analytics services.
Dependencies: pytest, services modules.
"""

import pytest

from core.models import CVEModel
from services.analytics import AnalyticsService
from services.export import ExportService
from services.sync import SyncService
from services.watchlist import WatchlistService
from storage.database import init_database
from storage.repositories import CVERepository


@pytest.fixture(autouse=True)
def setup_services_db(tmp_path):
    db_file = tmp_path / "test_services.db"
    init_database(db_url=f"sqlite:///{db_file}")


def test_export_service(tmp_path):
    cves = [
        CVEModel(
            id="CVE-2024-11111",
            summary="Export test vulnerability",
            severity="High",
            cvss=7.5,
            vendor="TestVendor",
        )
    ]
    exporter = ExportService()

    json_file = str(tmp_path / "report.json")
    out_json = exporter.export(cves, json_file, export_format="json")
    assert out_json == json_file

    csv_file = str(tmp_path / "report.csv")
    out_csv = exporter.export(cves, csv_file, export_format="csv")
    assert out_csv == csv_file

    md_file = str(tmp_path / "report.md")
    out_md = exporter.export(cves, md_file, export_format="markdown")
    assert out_md == md_file


def test_watchlist_service():
    w_service = WatchlistService()
    added = w_service.add_target(
        target_type="vendor",
        target_value="OpenSSL",
        notes="Watch OpenSSL",
    )
    assert added["target_value"] == "OpenSSL"

    targets = w_service.list_targets()
    assert len(targets) >= 1

    alerts = w_service.check_alerts()
    assert "alert_count" in alerts


def test_analytics_service():
    repo = CVERepository()
    repo.save(
        CVEModel(
            id="CVE-2024-22222",
            summary="Analytics vulnerability",
            severity="Critical",
            cvss=9.8,
        )
    )

    analytics = AnalyticsService(repo=repo)
    stats = analytics.get_summary_stats()
    assert stats["total_cves"] >= 1
    assert stats["critical"] >= 1


def test_sync_service_merges_kev_without_fake_epss_or_published_date():
    service = SyncService()
    kev = CVEModel(
        id="CVE-2024-33333",
        summary="KEV record",
        severity=None,
        cvss=None,
        exploit_available=True,
        epss=None,
        kev_date="2024-08-10",
        tags=["cisa_kev"],
        sources=["CISA KEV"],
    )
    nvd = CVEModel(
        id="CVE-2024-33333",
        summary="NVD record with richer data",
        severity="Critical",
        cvss=9.8,
        published="2024-01-01",
        updated="2024-02-01",
        references=["https://example.com/nvd"],
    )

    merged = service._merge_models(kev, nvd)
    assert merged.exploit_available is True
    assert merged.epss is None
    assert merged.kev_date == "2024-08-10"
    assert merged.published == "2024-01-01"
    assert merged.updated == "2024-02-01"
    assert merged.sources == ["CISA KEV"]


def test_sync_service_merges_epss_from_first_only():
    service = SyncService()
    nvd = CVEModel(id="CVE-2024-44444", summary="NVD", sources=["NVD"])
    epss = CVEModel(
        id="CVE-2024-44444",
        summary="",
        epss=0.42,
        epss_percentile=0.9,
        sources=["FIRST EPSS"],
    )

    merged = service._merge_models(nvd, epss)
    assert merged.epss == 0.42
    assert merged.epss_percentile == 0.9
    assert merged.sources == ["NVD", "FIRST EPSS"]


def test_sync_service_splits_nvd_date_range(monkeypatch):
    service = SyncService()
    calls = []

    def fake_fetch(query_params):
        calls.append(query_params)
        return []

    monkeypatch.setattr(service.nvd_adapter, "fetch_and_normalize", fake_fetch)
    service._fetch_nvd(
        {
            "keyword": "http",
            "resultsPerPage": 100,
            "pubStartDate": "2025-01-01T00:00:00.000Z",
            "pubEndDate": "2026-01-01T00:00:00.000Z",
        },
        100,
    )
    assert len(calls) == 4
