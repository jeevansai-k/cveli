"""
Unit Tests for CLI Commands.

Purpose: Test Typer CLI commands using CliRunner.
Dependencies: pytest, typer.testing.CliRunner, cli.app.
"""

import pytest
from rich.console import Console
from typer.testing import CliRunner

from cli.app import app
from cli.commands.search_cmd import (
    prompt_after_detail,
    resolve_cve_selection,
    resolve_search_range,
    search_cache_key,
)
from cli.tui.main import MainApp
from cli.tui.search_browser import SearchBrowserApp
from core.formatter import (
    build_reference_items,
    format_cve_detail_panel,
    format_cve_table,
)
from core.models import CVEModel
from storage.cache import cache_clear
from storage.database import init_database
from storage.repositories import CVERepository

runner = CliRunner()


@pytest.fixture(autouse=True)
def setup_cli_db(tmp_path):
    db_file = tmp_path / "test_cli.db"
    init_database(db_url=f"sqlite:///{db_file}")
    cache_clear()


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "cveli" in result.stdout


@pytest.mark.anyio
async def test_main_menu_shows_branding():
    main_app = MainApp()
    async with main_app.run_test():
        rendered = str(main_app.screen.query_one(".brand").render())
        assert "CVELI" in rendered
        assert "created by jeevansai-k" in rendered


def test_cli_short_help_alias():
    short_help = runner.invoke(app, ["-h"])
    long_help = runner.invoke(app, ["--help"])
    assert short_help.exit_code == 0
    assert long_help.exit_code == 0
    assert "CVELI" in short_help.stdout
    assert "created by jeevansai-k" in short_help.stdout
    assert "search" in short_help.stdout
    assert "search" in long_help.stdout


def test_subcommand_short_help_aliases():
    search_help = runner.invoke(app, ["search", "-h"])
    export_help = runner.invoke(app, ["export", "-h"])
    assert search_help.exit_code == 0
    assert export_help.exit_code == 0
    assert "CVELI" in export_help.stdout
    assert "created by jeevansai-k" in export_help.stdout
    assert "Search query keyword" in search_help.stdout
    assert "Export stored CVE records" in export_help.stdout
    assert "json, csv, markdown, or txt" in export_help.stdout
    assert "--output" in export_help.stdout


def test_cli_stats():
    repo = CVERepository()
    repo.save(
        CVEModel(
            id="CVE-2024-88888",
            summary="CLI stats test vuln",
            severity="High",
            cvss=7.8,
        )
    )

    result = runner.invoke(app, ["stats"])
    assert result.exit_code == 0
    assert "Total CVE Records" in result.stdout


def test_cli_watchlist():
    result_add = runner.invoke(
        app, ["watchlist", "add", "--type", "vendor", "--value", "OpenSSL"]
    )
    assert result_add.exit_code == 0
    assert "OpenSSL" in result_add.stdout

    result_list = runner.invoke(app, ["watchlist", "list"])
    assert result_list.exit_code == 0
    assert "OpenSSL" in result_list.stdout


def test_cli_search():
    repo = CVERepository()
    repo.save(
        CVEModel(
            id="CVE-2024-77777",
            summary="Test CLI search vulnerability",
            severity="Critical",
            cvss=9.8,
            vendor="TestVendor",
        )
    )
    seen = {}

    def fake_run(self):
        seen["results"] = self.pager.results

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(SearchBrowserApp, "run", fake_run)
        result = runner.invoke(
            app, ["search", "TestVendor", "--cache"], catch_exceptions=False
        )
    assert result.exit_code == 0
    assert seen["results"][0].id == "CVE-2024-77777"


def test_cli_search_zero_results_opens_empty_tui(monkeypatch):
    seen = {}

    def fake_search(self, *args, **kwargs):
        return []

    def fake_sync_sources(self, *args, **kwargs):
        return {"total_synced": 0, "sources": {"nvd": 0, "cisa_kev": 0}}

    def fake_run(self):
        seen["results"] = self.pager.results

    monkeypatch.setattr("storage.repositories.CVERepository.search", fake_search)
    monkeypatch.setattr("services.sync.SyncService.sync_sources", fake_sync_sources)
    monkeypatch.setattr(SearchBrowserApp, "run", fake_run)
    result = runner.invoke(
        app, ["search", "definitely-does-not-exist-123"], catch_exceptions=False
    )
    assert result.exit_code == 0
    assert seen["results"] == []


def test_search_results_have_serial_numbers():
    console = Console(record=True, width=120)
    table = format_cve_table(
        [
            CVEModel(id="CVE-2024-0001", summary="One", severity="High", cvss=7.5),
            CVEModel(id="CVE-2024-0002", summary="Two", severity="Medium", cvss=5.0),
        ]
    )
    console.print(table)
    output = console.export_text()
    assert "#" in output
    assert "1 " in output or " 1 " in output
    assert "2 " in output or " 2 " in output


def test_resolve_cve_selection_first_and_nth():
    assert resolve_cve_selection("1", 3) == 0
    assert resolve_cve_selection("3", 3) == 2


def test_resolve_cve_selection_invalid_values():
    with pytest.raises(ValueError):
        resolve_cve_selection("", 2)
    with pytest.raises(ValueError):
        resolve_cve_selection("abc", 2)
    with pytest.raises(ValueError):
        resolve_cve_selection("4", 2)
    assert resolve_cve_selection("q", 2) is None
    assert resolve_cve_selection("quit", 2) is None


def test_detail_render_contains_expected_fields_and_links():
    cve = CVEModel(
        id="CVE-2024-42424",
        summary="Detailed description for testing.",
        severity="Critical",
        cvss=9.8,
        published="2024-08-01",
        updated="2024-08-02",
        vendor="Fortinet",
        exploit_available=True,
        kev_date="2024-08-03",
        references=["https://fortinet.example/advisory"],
        tags=["cisa_kev"],
    )
    panel = format_cve_detail_panel(cve)
    console = Console(record=True, width=120)
    console.print(panel)
    output = console.export_text()
    assert "CVE-2024-42424" in output
    assert "Detailed description for testing." in output
    assert "CRITICAL" in output
    assert "9.8" in output

    links = {
        segment.style.link
        for segment in console.render(panel)
        if segment.style and segment.style.link
    }
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-42424" in links
    assert "https://www.cve.org/CVERecord?id=CVE-2024-42424" in links
    assert "https://fortinet.example/advisory" in links


def test_reference_items_include_known_links():
    items = build_reference_items(
        CVEModel(
            id="CVE-2024-55555", summary="x", references=["https://example.com/ref"]
        )
    )
    urls = [url for _, url in items]
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-55555" in urls
    assert "https://www.cve.org/CVERecord?id=CVE-2024-55555" in urls
    assert "https://example.com/ref" in urls


def test_detail_render_handles_missing_optional_fields():
    panel = format_cve_detail_panel(
        CVEModel(id="CVE-2024-66666", summary="Minimal record")
    )
    console = Console(record=True, width=120)
    console.print(panel)
    output = console.export_text()
    assert "CVE-2024-66666" in output
    assert "Minimal record" in output


def test_prompt_after_detail_quit(monkeypatch):
    console = Console()
    monkeypatch.setattr(console, "input", lambda *_args, **_kwargs: "q")
    assert prompt_after_detail(search_console=console) is False


def test_search_return_to_results_does_not_resync(monkeypatch):
    results = [
        CVEModel(
            id="CVE-2024-10101",
            summary="First vuln",
            severity="High",
            cvss=8.0,
            vendor="VendorA",
        ),
        CVEModel(
            id="CVE-2024-20202",
            summary="Second vuln",
            severity="Medium",
            cvss=5.0,
            vendor="VendorB",
        ),
    ]
    search_calls = {"count": 0}
    sync_calls = {"count": 0}

    def fake_search(self, *args, **kwargs):
        search_calls["count"] += 1
        return [] if search_calls["count"] == 1 else results

    def fake_sync_sources(self, *args, **kwargs):
        sync_calls["count"] += 1
        return {"total_synced": len(results), "sources": {"nvd": len(results)}}

    def fake_run(self):
        assert len(self.pager.results) == 2

    monkeypatch.setattr("storage.repositories.CVERepository.search", fake_search)
    monkeypatch.setattr("services.sync.SyncService.sync_sources", fake_sync_sources)
    monkeypatch.setattr(SearchBrowserApp, "run", fake_run)
    result = runner.invoke(app, ["search", "http"], catch_exceptions=False)
    assert result.exit_code == 0
    assert sync_calls["count"] == 1
    assert search_calls["count"] == 2


def test_search_range_values():
    assert resolve_search_range("1m")[0] == "1m"
    assert resolve_search_range("3m")[0] == "3m"
    assert resolve_search_range("6m")[0] == "6m"
    assert resolve_search_range("9m")[0] == "9m"
    assert resolve_search_range("1y")[0] == "1y"
    assert resolve_search_range("2y")[0] == "2y"
    assert resolve_search_range("3y")[0] == "3y"
    assert resolve_search_range("4y")[0] == "4y"
    assert resolve_search_range("5y")[0] == "5y"
    assert resolve_search_range("complete") == ("complete", None)


def test_search_cache_key_includes_range():
    one_year = search_cache_key("http", None, 0.0, None, None, False, 100, "1y")
    five_year = search_cache_key("http", None, 0.0, None, None, False, 100, "5y")
    assert one_year != five_year


def test_cli_search_uses_fresh_cache_without_sync(monkeypatch):
    cached = CVEModel(id="CVE-2024-12121", summary="Cached real CVE").to_dict()
    seen = {}

    def fail_sync(*_args, **_kwargs):
        raise AssertionError("sync should not run on fresh cache hit")

    def fake_run(self):
        seen["results"] = self.pager.results
        seen["source_note"] = self.source_note

    monkeypatch.setattr(
        "cli.commands.search_cmd.cache_get",
        lambda *_args: {"updated": "now", "results": [cached]},
    )
    monkeypatch.setattr("services.sync.SyncService.sync_sources", fail_sync)
    monkeypatch.setattr(SearchBrowserApp, "run", fake_run)

    result = runner.invoke(app, ["search", "http"], catch_exceptions=False)
    assert result.exit_code == 0
    assert seen["results"][0].id == "CVE-2024-12121"
    assert "Source: CACHE" in seen["source_note"]


def test_cli_search_explicit_live_bypasses_query_cache(monkeypatch):
    cached = CVEModel(id="CVE-2024-12121", summary="Cached CVE").to_dict()
    live_result = CVEModel(id="CVE-2024-34343", summary="Live CVE")
    search_calls = {"count": 0}
    sync_calls = {"count": 0}
    seen = {}

    def fake_search(self, *args, **kwargs):
        search_calls["count"] += 1
        return [] if search_calls["count"] == 1 else [live_result]

    def fake_sync_sources(self, *args, **kwargs):
        sync_calls["count"] += 1
        return {"total_synced": 1, "sources": {"nvd": 1}}

    def fake_run(self):
        seen["results"] = self.pager.results

    monkeypatch.setattr(
        "cli.commands.search_cmd.cache_get",
        lambda *_args: {"updated": "now", "results": [cached]},
    )
    monkeypatch.setattr("storage.repositories.CVERepository.search", fake_search)
    monkeypatch.setattr("services.sync.SyncService.sync_sources", fake_sync_sources)
    monkeypatch.setattr(SearchBrowserApp, "run", fake_run)

    result = runner.invoke(app, ["search", "http", "--live"], catch_exceptions=False)
    assert result.exit_code == 0
    assert sync_calls["count"] == 1
    assert seen["results"][0].id == "CVE-2024-34343"


def test_cli_search_does_not_print_http_logs(monkeypatch):
    def fake_search(self, *args, **kwargs):
        return []

    def fake_sync_sources(self, *args, **kwargs):
        return {"total_synced": 0, "sources": {"nvd": 0}}

    def fake_run(self):
        pass

    monkeypatch.setattr("storage.repositories.CVERepository.search", fake_search)
    monkeypatch.setattr("services.sync.SyncService.sync_sources", fake_sync_sources)
    monkeypatch.setattr(SearchBrowserApp, "run", fake_run)

    result = runner.invoke(app, ["search", "http"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "HTTP Request:" not in result.stdout
    assert "HTTP/1.1" not in result.stdout
