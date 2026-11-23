"""Regression tests for the user-reported issues fixed after the 2.0 release."""

import json
import re
from pathlib import Path

import pytest
from textual.widgets import Checkbox, DataTable, Input, OptionList
from typer.testing import CliRunner

from cli.app import app
from cli.tui.app import CveliApp
from cli.tui.widgets import (
    KEYS_CLOSE_HINT,
    CveliHelpPanel,
    ExportConfirmModal,
    ProjectPickerModal,
)
from core.dork_policy import validate_domain, validate_username
from core.dork_templates import SITE_PRESETS
from core.models import CVEModel, DorkInput, ExploitModel
from services.dorks import DorkBuilder
from services.projects import ProjectService
from services.watchlist import WatchlistService
from storage.repositories import CVERepository
from storage.research_repositories import DorkRepository

runner = CliRunner()
ROOT = Path(__file__).resolve().parent.parent


async def settle(app_, pilot):
    try:
        await app_.workers.wait_for_complete()
    except Exception:
        await app_.workers.wait_for_complete()
    await pilot.pause()


# --- 1. Add to an existing project -----------------------------------------


@pytest.mark.anyio
async def test_exploit_add_to_existing_project():
    from cli.tui.views.exploits import ExploitDetailScreen

    ProjectService().create("Existing case")
    ProjectService().create("Other case")
    exploit = ExploitModel(edb_id=4242, title="Acme 1.0 - RCE", safety_labels=[])
    app_ = CveliApp()
    async with app_.run_test(size=(150, 50)) as pilot:
        app_.push_screen(ExploitDetailScreen(exploit))
        await pilot.pause()
        app_.screen.action_add_to_project()
        await pilot.pause()
        assert isinstance(app_.screen, ProjectPickerModal)
        options = app_.screen.query_one("#project_choices", OptionList)
        prompts = [str(options.get_option_at_index(i).prompt) for i in range(2)]
        assert any("Existing case" in p for p in prompts)
        options.focus()
        options.highlighted = next(
            i for i, p in enumerate(prompts) if "Existing case" in p
        )
        await pilot.press("enter")
        await pilot.pause()
    project = ProjectService().show("Existing case")
    assert [(i["kind"], i["ref_id"]) for i in project["items"]] == [("exploit", "4242")]
    names = [p["name"] for p in ProjectService().list()]
    assert "Default research" not in names


@pytest.mark.anyio
async def test_picker_can_create_new_project():
    from cli.tui.search_browser import SearchBrowserApp

    cve = CVEModel(id="CVE-2024-1111", summary="x")
    app_ = SearchBrowserApp([cve])
    async with app_.run_test(size=(150, 50)) as pilot:
        await pilot.press("1", "enter")
        await pilot.press("p")
        await pilot.pause()
        assert isinstance(app_.screen, ProjectPickerModal)
        app_.screen.query_one("#new_project_name", Input).value = "Fresh case"
        app_.screen.query_one("#create_project").press()
        await pilot.pause()
    items = ProjectService().show("Fresh case")["items"]
    assert items[0]["ref_id"] == "CVE-2024-1111"


@pytest.mark.anyio
async def test_dork_save_goes_to_chosen_project():
    ProjectService().create("OSINT case")
    app_ = CveliApp()
    async with app_.run_test(size=(150, 60)) as pilot:
        view = app_.show_view("dorks")
        view.query_one("#dork_username", Input).value = "alice"
        view.build()
        await pilot.pause()
        view.save(view.dorks[0])
        await pilot.pause()
        assert isinstance(app_.screen, ProjectPickerModal)
        options = app_.screen.query_one("#project_choices", OptionList)
        options.focus()
        options.highlighted = 0
        await pilot.press("enter")
        await pilot.pause()
    saved = DorkRepository().list()
    assert len(saved) == 1
    assert ProjectService().show("OSINT case")["dorks"][0]["username"] == "alice"


@pytest.mark.anyio
async def test_cve_search_view_add_to_project():
    CVERepository().save(
        CVEModel(id="CVE-2024-2222", summary="acme bug", vendor="acme", sources=["NVD"])
    )
    ProjectService().create("Case 9")
    app_ = CveliApp()
    async with app_.run_test(size=(150, 50)) as pilot:
        view = app_.show_view("search")
        await settle(app_, pilot)
        view.query_one("#cve_results", DataTable).focus()
        await pilot.press("p")
        await pilot.pause()
        assert isinstance(app_.screen, ProjectPickerModal)
        await pilot.press("enter")
        await pilot.pause()
    assert ProjectService().show("Case 9")["items"][0]["ref_id"] == "CVE-2024-2222"


# --- 2. Choose export file types --------------------------------------------


@pytest.mark.anyio
async def test_export_modal_lets_user_choose_formats(tmp_path):
    from cli.tui.views.templates import TemplatePreview

    CVERepository().save(
        CVEModel(
            id="CVE-2024-3333", summary="x", published="2024-01-01", sources=["NVD"]
        )
    )
    app_ = CveliApp()
    async with app_.run_test(size=(160, 60)) as pilot:
        view = app_.show_view("templates")
        view.query_one("#tpl_cve", Input).value = "CVE-2024-3333"
        view.generate()
        await settle(app_, pilot)
        preview = view.query_one(TemplatePreview)
        preview.query_one("#tpl_out", Input).value = str(tmp_path / "out")
        preview.request_export()
        await pilot.pause()
        modal = app_.screen
        assert isinstance(modal, ExportConfirmModal)
        for fmt in ("rb", "md", "json"):
            assert modal.query_one(f"#fmt_{fmt}", Checkbox).value
        modal.query_one("#fmt_rb", Checkbox).value = False
        modal.query_one("#fmt_md", Checkbox).value = False
        modal.query_one("#attest", Checkbox).value = True
        await pilot.pause()
        modal.query_one("#confirm").press()
        await pilot.pause()
    files = sorted(p.suffix for p in (tmp_path / "out").iterdir())
    assert files == [".json"]


@pytest.mark.anyio
async def test_export_modal_requires_a_format():
    from textual.app import App

    class Host(App):
        def on_mount(self):
            self.push_screen(ExportConfirmModal("t", "b", "attest"))

    host = Host()
    async with host.run_test() as pilot:
        modal = host.screen
        modal.query_one("#attest", Checkbox).value = True
        for fmt in ("rb", "md", "json"):
            modal.query_one(f"#fmt_{fmt}", Checkbox).value = False
        await pilot.pause()
        assert modal.query_one("#confirm").disabled
        modal.query_one("#fmt_md", Checkbox).value = True
        await pilot.pause()
        assert not modal.query_one("#confirm").disabled
        assert modal.result() == ["md"]


# --- 3. Remove a watchlist entry ---------------------------------------------


@pytest.mark.anyio
async def test_watchlist_remove_button():
    WatchlistService().add_target("vendor", "Fortinet")
    app_ = CveliApp()
    async with app_.run_test(size=(150, 50)) as pilot:
        view = app_.show_view("watchlist")
        await pilot.pause()
        table = view.query_one("#watchlist_table", DataTable)
        table.focus()
        table.move_cursor(row=0)
        await pilot.pause()
        button = view.query_one("#remove_target_btn")
        assert not button.disabled
        button.press()
        await pilot.pause()
        app_.screen.query_one("#attest", Checkbox).value = True
        await pilot.pause()
        app_.screen.query_one("#confirm").press()
        await pilot.pause()
        assert table.row_count == 0
    assert WatchlistService().list_targets() == []


# --- 4. Theme names -------------------------------------------------------------


@pytest.mark.anyio
async def test_theme_names_are_dark_and_light():
    app_ = CveliApp()
    async with app_.run_test(size=(150, 50)):
        assert set(app_.available_themes) == {"dark", "light"}
        view = app_.show_view("settings")
        labels = [str(b.label) for b in view.query("RadioButton")]
        assert labels[:2] == ["Dark", "Light"]
        assert not any("Opus" in label for label in labels)


def test_cli_theme_label():
    runner.invoke(app, ["settings", "theme", "dark"])
    out = runner.invoke(app, ["settings", "theme"]).stdout
    assert "active: Dark" in out and "opus" not in out.lower()


# --- 5 + 6. Social media dorks ---------------------------------------------------


def test_social_sites_in_dropdown():
    domains = {domain for _label, domain in SITE_PRESETS}
    for expected in (
        "snapchat.com",
        "instagram.com",
        "facebook.com",
        "tiktok.com",
        "x.com",
        "threads.net",
        "reddit.com",
        "youtube.com",
        "linkedin.com",
        "pinterest.com",
        "t.me",
        "bsky.app",
    ):
        assert expected in domains


def test_snapchat_profile_dorks():
    dorks = DorkBuilder().build(
        DorkInput(username="@alice_snaps", target_domain="snapchat.com")
    )
    queries = {d.id: d.query for d in dorks}
    assert queries["platform_profile_url"] == (
        'site:snapchat.com (inurl:"add/alice_snaps" OR inurl:"@alice_snaps")'
    )
    assert queries["platform_handle_mention"] == 'site:snapchat.com "@alice_snaps"'
    assert all(d.username == "alice_snaps" for d in dorks)


@pytest.mark.parametrize(
    ("site", "expected"),
    [
        ("tiktok.com", 'site:tiktok.com inurl:"@alice"'),
        ("instagram.com", 'site:instagram.com inurl:"alice"'),
        ("x.com", '(site:x.com OR site:twitter.com) inurl:"alice"'),
        ("reddit.com", 'site:reddit.com (inurl:"user/alice" OR inurl:"u/alice")'),
        ("linkedin.com", 'site:linkedin.com inurl:"in/alice"'),
        ("bsky.app", 'site:bsky.app inurl:"profile/alice"'),
    ],
)
def test_platform_profile_patterns(site, expected):
    dork = DorkBuilder().build(DorkInput(username="alice", target_domain=site))[0]
    assert dork.query == expected


@pytest.mark.parametrize(
    ("raw", "domain"),
    [
        ("snapchat", "snapchat.com"),
        ("Snapchat", "snapchat.com"),
        ("twitter", "x.com"),
        ("telegram", "t.me"),
        ("https://www.snapchat.com/add/alice", "snapchat.com"),
        ("m.facebook.com", "facebook.com"),
    ],
)
def test_platform_names_and_urls_accepted(raw, domain):
    assert validate_domain(raw) == domain


def test_at_handle_accepted():
    assert validate_username("@alice") == "alice"


def test_social_category_needs_no_site():
    dorks = DorkBuilder().build(DorkInput(username="alice", category="social"))
    ids = [d.id for d in dorks]
    assert ids[0] == "social_footprint"
    assert "social_snapchat" in ids and "social_tiktok" in ids
    assert "site:snapchat.com" in dorks[0].query
    assert all(d.risk_level == "low" for d in dorks)


def test_cli_social_dork_without_site():
    result = runner.invoke(
        app, ["dork", "build", "-u", "@alice", "-c", "social", "-f", "json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert any(d["id"] == "social_snapchat" for d in payload)
    snap = runner.invoke(
        app, ["dork", "build", "-u", "alice", "-s", "snapchat", "-f", "plain"]
    )
    assert 'inurl:"add/alice"' in snap.stdout


def test_social_dorks_still_block_secrets():
    from utils.errors import PolicyError

    with pytest.raises(PolicyError):
        DorkBuilder().build(
            DorkInput(username="alice", category="social", include_phrases=["password"])
        )


# --- 7. Keys guide hint ---------------------------------------------------------


@pytest.mark.anyio
async def test_keys_panel_shows_close_hint():
    assert KEYS_CLOSE_HINT == "To close this page select [keys] from palette again"
    app_ = CveliApp()
    async with app_.run_test(size=(150, 50)) as pilot:
        keys = next(
            c for c in app_.get_system_commands(app_.screen) if c.title == "Keys"
        )
        keys.callback()
        await pilot.pause()
        panel = app_.screen.query_one(CveliHelpPanel)
        assert str(panel.query_one("#keys-close-hint").render()) == KEYS_CLOSE_HINT
        hide = next(
            c for c in app_.get_system_commands(app_.screen) if c.title == "Keys"
        )
        hide.callback()
        await pilot.pause()
        assert not app_.screen.query("HelpPanel")


# --- 8. Clean borders and scrollbars ---------------------------------------------


def test_stylesheet_uses_box_drawing_borders():
    css = (ROOT / "cli" / "tui" / "cveli.tcss").read_text()
    rules = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    assert not re.search(r"border[\w-]*:\s*(tall|wide|thick|hkey|vkey)\b", rules)
    assert "scrollbar-size-vertical: 1" in rules


@pytest.mark.anyio
async def test_controls_render_box_borders_and_thin_scrollbars():
    app_ = CveliApp()
    async with app_.run_test(size=(150, 50)) as pilot:
        view = app_.show_view("exploits")
        await settle(app_, pilot)
        for selector in ("#edb_text", "#edb_verified", "#edb_prev", "#edb_results"):
            widget = view.query_one(selector)
            assert widget.styles.border_left[0] == "round", selector
        assert view.styles.scrollbar_size_vertical == 1
        text = view.query_one("#edb_text")
        before = text.region
        text.focus()
        await pilot.pause()
        assert text.region == before  # focus changes colour only, never layout
