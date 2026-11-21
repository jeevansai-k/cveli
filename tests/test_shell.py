"""TUI shell: navigation, keyboard access, theme switching, error states."""

import pytest
from textual.widgets import ContentSwitcher, DataTable, Input, Static

from cli.tui.app import CveliApp
from cli.tui.theme import DARK, LIGHT
from core.models import CVEModel
from storage.repositories import CVERepository
from storage.system_repositories import SettingsRepository


def seed():
    CVERepository().save(
        CVEModel(
            id="CVE-2024-5555",
            summary="Shell test vuln",
            severity="Critical",
            cvss=9.1,
            published="",
            vendor="acme",
            sources=["NVD"],
        )
    )


@pytest.mark.anyio
async def test_shell_starts_on_dashboard_with_branding():
    app = CveliApp()
    async with app.run_test(size=(140, 45)):
        assert app.query_one("#workspace", ContentSwitcher).current == "dashboard"
        brand = str(app.screen.query_one(".brand").render())
        assert "CVELI" in brand and "created by jeevansai-k" in brand


@pytest.mark.anyio
async def test_number_keys_switch_views():
    app = CveliApp()
    async with app.run_test(size=(140, 45)) as pilot:
        ids = app.view_ids()
        for index, view_id in enumerate(ids[:4], start=1):
            app.set_focus(None)
            await pilot.press(str(index))
            await pilot.pause()
            assert app.query_one("#workspace", ContentSwitcher).current == view_id


@pytest.mark.anyio
async def test_typing_digits_in_search_does_not_navigate():
    app = CveliApp()
    async with app.run_test(size=(140, 45)) as pilot:
        app.query_one("#nav").focus()
        await pilot.press("slash")
        assert isinstance(app.focused, Input)
        await pilot.press("2", "0", "2", "4")
        assert app.query_one("#global_search", Input).value == "2024"
        assert app.query_one("#workspace", ContentSwitcher).current == "dashboard"


@pytest.mark.anyio
async def test_global_search_routes_to_search_view():
    seed()
    app = CveliApp()
    async with app.run_test(size=(140, 45)) as pilot:
        app.query_one("#search").query_one("#cve_live").value = False
        app.route_query("acme")
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert app.query_one("#workspace", ContentSwitcher).current == "search"
        table = app.query_one("#cve_results", DataTable)
        assert table.row_count >= 1


@pytest.mark.anyio
async def test_theme_toggle_persists():
    app = CveliApp()
    async with app.run_test(size=(120, 40)) as pilot:
        start = app.theme
        await pilot.press("ctrl+t")
        assert app.theme != start
        assert app.theme in (DARK, LIGHT)
        assert SettingsRepository().get("theme") in ("dark", "light")


@pytest.mark.anyio
async def test_saved_light_theme_applied_on_start():
    SettingsRepository().set("theme", "light")
    app = CveliApp()
    async with app.run_test(size=(120, 40)):
        assert app.theme == LIGHT


@pytest.mark.anyio
async def test_watchlist_invalid_type_shows_error_not_crash():
    app = CveliApp()
    async with app.run_test(size=(140, 45)) as pilot:
        view = app.show_view("watchlist")
        view.query_one("#target_value_input", Input).value = ""
        view._add()
        await pilot.pause()
        assert app.is_running
        assert any("Target value" in str(n.message) for n in app._notifications)


@pytest.mark.anyio
async def test_narrow_terminal_hides_intel_panel():
    app = CveliApp()
    async with app.run_test(size=(70, 30)):
        assert app.screen.has_class("-narrow")
        assert app.query_one("#intel").styles.display == "none"


@pytest.mark.anyio
async def test_tab_reaches_navigation_and_workspace():
    app = CveliApp()
    async with app.run_test(size=(140, 45)) as pilot:
        seen = set()
        for _ in range(12):
            await pilot.press("tab")
            if app.focused is not None:
                seen.add(app.focused.id or type(app.focused).__name__)
        assert "global_search" in seen
        assert "nav" in seen


@pytest.mark.anyio
async def test_source_status_shows_placeholders():
    app = CveliApp()
    async with app.run_test(size=(140, 45)):
        text = str(app.query_one("#source_status", Static).render())
        assert "NVD" in text and "KEV" in text
