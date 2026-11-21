"""Regression tests for the bugs on docs/triage.md (B1-B17)."""

import json
import os
from datetime import timedelta
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from cli.app import app
from core.formatter import (
    format_cve_detail_panel,
    format_cve_markdown,
    format_cve_table,
)
from core.merge import merge_models
from core.models import CVEModel, Reference
from core.text import sanitize_terminal_text
from services.export import ExportService, csv_safe, validate_output_path
from services.sync import SyncService
from services.watchlist import WatchlistService
from sources.epss import EPSSAdapter
from sources.nvd import NVDAdapter
from storage.database import CVERecord, get_session
from storage.repositories import CVERepository
from storage.system_repositories import SourceStateRepository
from utils.errors import ValidationError

runner = CliRunner()


def nvd_model(cve_id="CVE-2024-1000", **kw):
    base = {
        "id": cve_id,
        "summary": "NVD description of a heap overflow",
        "severity": "High",
        "cvss": 8.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "published": "2024-01-02",
        "updated": "2024-02-03",
        "vendor": "acme",
        "sources": ["NVD"],
    }
    base.update(kw)
    return CVEModel(**base)


def kev_model(cve_id="CVE-2024-1000"):
    return CVEModel(
        id=cve_id,
        summary="Short KEV text",
        kev=True,
        kev_date="2024-03-04",
        tags=["cisa_kev"],
        sources=["CISA KEV"],
    )


# --- B1 -----------------------------------------------------------------------


def test_kev_resave_preserves_nvd_fields():
    repo = CVERepository()
    repo.save(nvd_model())
    repo.save(kev_model())
    stored = repo.get_by_id("CVE-2024-1000")
    assert stored.cvss == 8.1
    assert stored.severity == "High"
    assert stored.published == "2024-01-02"
    assert stored.summary == "NVD description of a heap overflow"
    assert stored.kev is True
    assert stored.kev_date == "2024-03-04"
    assert set(stored.sources) == {"NVD", "CISA KEV"}


def test_epss_only_save_keeps_everything_else():
    repo = CVERepository()
    repo.save(nvd_model())
    repo.save(
        CVEModel(
            id="CVE-2024-1000",
            summary="",
            epss=0.5,
            epss_percentile=0.9,
            sources=["FIRST EPSS"],
        )
    )
    stored = repo.get_by_id("CVE-2024-1000")
    assert stored.cvss == 8.1 and stored.epss == 0.5 and stored.vendor == "acme"


def test_newer_nvd_rescore_replaces_old_score():
    repo = CVERepository()
    repo.save(nvd_model())
    repo.save(nvd_model(cvss=6.5, severity="Medium", updated="2024-05-01"))
    stored = repo.get_by_id("CVE-2024-1000")
    assert stored.cvss == 6.5 and stored.severity == "Medium"
    assert stored.updated == "2024-05-01"


def test_merge_unions_reference_details():
    a = nvd_model(reference_details=[Reference(url="https://a", tags=["Patch"])])
    b = nvd_model(reference_details=[Reference(url="https://a", tags=["Vendor"])])
    merged = merge_models(a, b)
    assert merged.reference_details[0].tags == ["Patch", "Vendor"]


def test_save_bulk_is_single_transaction(monkeypatch):
    calls = {"n": 0}
    import storage.repositories as repos

    real = repos.get_session

    def counting():
        calls["n"] += 1
        return real()

    monkeypatch.setattr(repos, "get_session", counting)
    CVERepository().save_bulk(
        [nvd_model(f"CVE-2024-{i:04d}") for i in range(1000, 1050)]
    )
    assert calls["n"] == 1


# --- B2 -----------------------------------------------------------------------


def test_env_nvd_key_sent(monkeypatch, httpx_mock):
    monkeypatch.setenv("NVD_API_KEY", "secret-key-123")
    from config.settings import reset_settings

    reset_settings()
    httpx_mock.add_response(json={"totalResults": 0, "vulnerabilities": []})
    SyncService().sync_sources(sources=["nvd"], query="CVE-2024-0001")
    request = httpx_mock.get_requests()[0]
    assert request.headers["apiKey"] == "secret-key-123"
    assert "cveli/2.0.0" in request.headers["User-Agent"]


# --- B5 -----------------------------------------------------------------------


def test_range_filters_local(monkeypatch):
    repo = CVERepository()
    repo.save(nvd_model("CVE-2019-0001", published="2019-01-01"))
    repo.save(nvd_model("CVE-2099-0001", published="2026-11-01"))
    since = "2025-12-01T00:00:00.000Z"
    ids = {c.id for c in repo.search(published_since=since)}
    assert ids == {"CVE-2099-0001"}
    ids_all = {c.id for c in repo.search()}
    assert ids_all == {"CVE-2019-0001", "CVE-2099-0001"}


def test_range_includes_recent_kev_only_rows():
    repo = CVERepository()
    repo.save(kev_model("CVE-2018-0001"))
    with get_session() as session:
        row = session.get(CVERecord, "CVE-2018-0001")
        assert row.published_date is None
    assert repo.search(published_since="2024-01-01T00:00:00.000Z")


# --- B6 -----------------------------------------------------------------------


def _nvd_page(ids, total):
    return {
        "totalResults": total,
        "vulnerabilities": [
            {"cve": {"id": cve_id, "descriptions": [{"lang": "en", "value": "x"}]}}
            for cve_id in ids
        ],
    }


def test_nvd_paginates_until_total(httpx_mock, monkeypatch):
    monkeypatch.setattr("sources.nvd.NVD_MAX_PAGE", 2)
    httpx_mock.add_response(json=_nvd_page(["CVE-2024-0001", "CVE-2024-0002"], 5))
    httpx_mock.add_response(json=_nvd_page(["CVE-2024-0003", "CVE-2024-0004"], 5))
    httpx_mock.add_response(json=_nvd_page(["CVE-2024-0005"], 5))
    models = NVDAdapter().fetch_and_normalize({"keyword": "x", "resultsPerPage": 50})
    assert [m.id for m in models] == [f"CVE-2024-000{i}" for i in range(1, 6)]
    starts = [r.url.params.get("startIndex") for r in httpx_mock.get_requests()]
    assert starts == [None, "2", "4"]


def test_nvd_respects_limit(httpx_mock):
    httpx_mock.add_response(json=_nvd_page(["CVE-2024-0001", "CVE-2024-0002"], 900))
    models = NVDAdapter().fetch_and_normalize({"keyword": "x", "resultsPerPage": 2})
    assert len(models) == 2
    assert len(httpx_mock.get_requests()) == 1


def test_nvd_captures_reference_tags_and_sanitizes():
    norm = NVDAdapter().normalize(
        {
            "id": "CVE-2024-1",
            "descriptions": [{"lang": "en", "value": "bad\x1b[31m red\x07"}],
            "references": [{"url": "https://p", "source": "x", "tags": ["Patch"]}],
        }
    )
    assert norm["summary"] == "bad red"
    assert norm["reference_details"][0]["tags"] == ["Patch"]


# --- B7 -----------------------------------------------------------------------


def test_kev_cached_between_syncs(httpx_mock):
    kev = {"vulnerabilities": [{"cveID": "CVE-2024-1", "dateAdded": "2024-01-01"}]}
    httpx_mock.add_response(json=kev)
    first = SyncService().sync_sources(sources=["cisa_kev"])
    second = SyncService().sync_sources(sources=["cisa_kev"])
    assert first["sources"]["cisa_kev"] == 1
    assert second["sources"]["cisa_kev"] == 0
    assert len(httpx_mock.get_requests()) == 1
    assert not SourceStateRepository().is_stale("cisa_kev", 24)


def test_kev_refresh_forced(httpx_mock):
    kev = {"vulnerabilities": [{"cveID": "CVE-2024-1", "dateAdded": "2024-01-01"}]}
    httpx_mock.add_response(json=kev)
    httpx_mock.add_response(json=kev)
    SyncService().sync_sources(sources=["cisa_kev"])
    SyncService().sync_sources(sources=["cisa_kev"], force=True)
    assert len(httpx_mock.get_requests()) == 2


def test_epss_batched(httpx_mock):
    ids = [f"CVE-2024-{i:04d}" for i in range(1000, 1250)]
    for _ in range(3):
        httpx_mock.add_response(json={"data": []})
    EPSSAdapter().fetch_and_normalize({"cves": ids})
    requests = httpx_mock.get_requests()
    assert len(requests) == 3
    assert all(len(r.url.params["cve"].split(",")) <= 100 for r in requests)


# --- B8 -----------------------------------------------------------------------


def test_sanitize_terminal_text():
    raw = "ok\x1b[2J\x1b]8;;http://evil\x07link\x1b]8;;\x07\x00 done"
    assert sanitize_terminal_text(raw) == "oklink done"


def test_watchlist_markup_escaped():
    CVERepository().save(
        nvd_model(summary="[bold red]INJECTED[/bold red] \x1b[31mansi", vendor="acme")
    )
    WatchlistService().add_target("vendor", "acme")
    result = runner.invoke(app, ["watchlist", "check"])
    assert result.exit_code == 0
    assert "[bold red]INJECTED[/bold red]" in result.stdout
    assert "\x1b[31m" not in result.stdout


def test_table_and_panel_do_not_parse_markup():
    cve = nvd_model(summary="[link=http://evil]click[/link]", vendor="[red]x[/red]")
    console = Console(record=True, width=160)
    console.print(format_cve_table([cve]))
    console.print(format_cve_detail_panel(cve))
    text = console.export_text()
    assert "[link=http://evil]click[/link]" in text


def test_markdown_export_escapes_links():
    md = format_cve_markdown(
        [nvd_model(summary="see [x](javascript:alert(1))", references=["javascript:1"])]
    )
    assert "](javascript" not in md
    assert "javascript:1" not in md


# --- B9 -----------------------------------------------------------------------


def test_export_path_rejects_system_dirs():
    with pytest.raises(ValidationError):
        validate_output_path("/etc/cveli.json")
    with pytest.raises(ValidationError):
        validate_output_path("/usr/../etc/passwd")


def test_export_path_rejects_symlink(tmp_path):
    target = tmp_path / "real.json"
    target.write_text("{}")
    link = tmp_path / "link.json"
    os.symlink(target, link)
    with pytest.raises(ValidationError):
        validate_output_path(str(link))


def test_export_path_outside_safe_roots_needs_force(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "home")
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path / "tmp"))
    monkeypatch.chdir(tmp_path / ".." if False else tmp_path)
    outside = Path("/srv/cveli-test-out/report.json")
    with pytest.raises(ValidationError):
        validate_output_path(str(outside))


def test_csv_formula_injection_neutralised(tmp_path):
    out = tmp_path / "x.csv"
    ExportService().export(
        [nvd_model(summary='=HYPERLINK("http://evil")', vendor="+cmd")],
        str(out),
        "csv",
    )
    content = out.read_text()
    assert "'=HYPERLINK" in content and "'+cmd" in content
    assert csv_safe("normal") == "normal"


# --- B10 / B11 / B12 ----------------------------------------------------------


def test_invalid_severity_rejected():
    result = runner.invoke(app, ["search", "x", "--cache", "--severity", "nuclear"])
    assert result.exit_code != 0
    assert "severity" in result.output.lower()


def test_watchlist_invalid_type_cli_clean_error():
    result = runner.invoke(app, ["watchlist", "add", "--type", "foo", "--value", "x"])
    assert result.exit_code == 2
    assert "Target type" in result.stdout


def test_search_non_tty_prints_table(monkeypatch):
    CVERepository().save(nvd_model(published=""))

    def boom(self):
        raise AssertionError("TUI must not start without a TTY")

    monkeypatch.setattr("cli.tui.search_browser.SearchBrowserApp.run", boom)
    result = runner.invoke(app, ["search", "acme", "--cache"])
    assert result.exit_code == 0
    assert "CVE-2024-1000" in result.stdout


def test_search_json_is_machine_readable():
    CVERepository().save(nvd_model(published=""))
    result = runner.invoke(app, ["search", "acme", "--cache", "--format", "json"])
    assert json.loads(result.stdout)[0]["id"] == "CVE-2024-1000"


def test_kev_and_public_exploit_flags():
    kev = kev_model("CVE-2024-2000")
    assert kev.kev and kev.exploit_available and kev.public_exploit_count == 0
    public = CVEModel(id="CVE-2024-3000", summary="x", public_exploit_count=2)
    assert not public.kev and public.exploit_available
    repo = CVERepository()
    repo.save_bulk([kev, public, nvd_model("CVE-2024-4000")])
    assert {c.id for c in repo.search(kev_only=True)} == {"CVE-2024-2000"}
    assert {c.id for c in repo.search(public_exploit_only=True)} == {"CVE-2024-3000"}


def test_deprecated_exploits_flag_maps_to_kev():
    CVERepository().save_bulk([kev_model("CVE-2024-2000"), nvd_model(published="")])
    result = runner.invoke(
        app,
        ["search", "", "--cache", "--exploits", "--range", "complete", "-f", "json"],
    )
    ids = [row["id"] for row in json.loads(result.stdout)]
    assert ids == ["CVE-2024-2000"]


# --- B15 ----------------------------------------------------------------------


def test_watchlist_reports_new_since_last_check():
    service = WatchlistService()
    repo = CVERepository()
    repo.save(nvd_model("CVE-2024-0001"))
    service.add_target("vendor", "acme")
    first = service.check_alerts()
    assert first["new_total"] == 1
    second = service.check_alerts()
    assert second["new_total"] == 0
    with get_session() as session:
        from storage.database import WatchlistItemRecord, utcnow

        now = utcnow()
        session.get(CVERecord, "CVE-2024-0001").first_seen_at = now - timedelta(
            seconds=10
        )
        session.query(WatchlistItemRecord).one().last_checked_at = now - timedelta(
            seconds=5
        )
    repo.save(nvd_model("CVE-2024-0002"))
    third = service.check_alerts()
    assert third["new_total"] == 1
    assert third["alerts"][0]["new_cve_ids"] == ["CVE-2024-0002"]


def test_watchlist_cwe_normalised():
    added = WatchlistService().add_target("cwe", "79")
    assert added["target_value"] == "CWE-79"
    with pytest.raises(ValidationError):
        WatchlistService().add_target("cwe", "XSS")
