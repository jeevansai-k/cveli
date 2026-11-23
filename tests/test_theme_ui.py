"""Opus 5.5 theme QA: visual snapshots (dark + light), palette, motion, NO_COLOR."""

import pytest
from typer.testing import CliRunner

from cli.app import app
from cli.tui.app import CveliApp
from storage.system_repositories import SettingsRepository

runner = CliRunner()
VIEWS = ["dashboard", "dorks", "templates", "watchlist"]


def _shell(theme: str) -> CveliApp:
    SettingsRepository().set("theme", theme)
    return CveliApp()


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("view", VIEWS)
def test_view_snapshots(snap_compare, theme, view):
    async def prepare(pilot):
        shown = pilot.app.show_view(view)
        if view == "dorks":
            shown.query_one("#dork_username").value = "alice"
            shown.build()
        pilot.app.set_focus(None)
        await pilot.pause()

    assert snap_compare(_shell(theme), terminal_size=(140, 44), run_before=prepare)


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_narrow_snapshot(snap_compare, theme):
    async def prepare(pilot):
        pilot.app.set_focus(None)
        await pilot.pause()

    assert snap_compare(_shell(theme), terminal_size=(76, 30), run_before=prepare)


@pytest.mark.anyio
async def test_narrow_nav_is_compact_and_restores():
    app_ = CveliApp()
    async with app_.run_test(size=(76, 30)) as pilot:
        nav = app_.query_one("#nav")
        assert "Dashboard" not in str(nav.get_option_at_index(0).prompt)
        await pilot.resize_terminal(140, 44)
        await pilot.pause()
        assert "Dashboard" in str(nav.get_option_at_index(0).prompt)


@pytest.mark.anyio
async def test_command_palette_lists_cveli_commands():
    from cli.tui.commands import CveliCommands

    app_ = CveliApp()
    async with app_.run_test(size=(140, 44)):
        provider = CveliCommands(app_.screen)
        names = [str(hit.display) async for hit in provider.discover()]
        assert "Go to Exploit-DB" in names
        assert "Theme: Light" in names
        hits = [hit async for hit in provider.search("CVE-2021-44228")]
        assert any("Open CVE-2021-44228" in str(hit.text) for hit in hits)
        theme_hit = next(
            h
            for h in [h async for h in provider.discover()]
            if str(h.display) == "Theme: Light"
        )
        theme_hit.command()
        assert app_.theme == "light"


@pytest.mark.anyio
async def test_reduced_motion_setting_disables_animation():
    SettingsRepository().set("reduce_motion", True)
    app_ = CveliApp()
    async with app_.run_test(size=(120, 40)):
        assert app_.animation_level == "none"


@pytest.mark.anyio
async def test_focus_ring_uses_theme_token():
    from cli.tui.theme import OPUS_DARK

    app_ = CveliApp()
    async with app_.run_test(size=(140, 44)) as pilot:
        await pilot.press("slash")
        search = app_.query_one("#global_search")
        assert app_.focused is search
        color = search.styles.border_top[1]
        assert color.hex.lower() == OPUS_DARK.focus.lower()


def test_no_color_cli_output(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    import cli.console as console_module

    monkeypatch.setattr(console_module, "_console", None)
    console = console_module.get_console()
    assert console.no_color is True


def test_cli_theme_flag_and_settings_command():
    assert runner.invoke(app, ["settings", "theme", "light"]).exit_code == 0
    assert SettingsRepository().get("theme") == "light"
    shown = runner.invoke(app, ["settings", "theme"])
    assert "active: Light" in shown.stdout
    bad = runner.invoke(app, ["settings", "theme", "neon"])
    assert bad.exit_code != 0
    assert runner.invoke(app, ["--theme", "dark", "version"]).exit_code == 0
