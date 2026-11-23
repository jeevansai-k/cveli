"""Social-media Dork Builder: reliability across platforms, inputs and the TUI."""

import pytest
from textual.widgets import Input, Select

from cli.tui.app import CveliApp
from core.dork_policy import evaluate
from core.dork_templates import CATEGORIES, SITE_PRESETS, explain_operators
from core.models import DorkInput
from core.social_platforms import SOCIAL_PLATFORMS, handle_for, platform_for
from services.dorks import DorkBuilder
from utils.errors import PolicyError

USERNAMES = [
    "alice",
    "@alice",
    "Alice.Smith",
    "alice_99",
    "john-doe",
    "Cristiano Ronaldo",
    "a1",
    "x" * 30,
    "dumpling_leaks",
    "tokenizer",
    "passwordless",
    "secret",
    "admin",
    "Zoë",
    "李明",
    "user@mail",
    "the.rock",
    "mr.beast_",
]
TEXT_CATEGORIES = [
    c for c in CATEGORIES if c not in {"custom", "subdomains", "login", "directories"}
]


def build(**kwargs):
    return DorkBuilder(opener=lambda url: True).build(DorkInput(**kwargs))


@pytest.mark.parametrize("platform", SOCIAL_PLATFORMS, ids=lambda p: p.domain)
def test_every_platform_every_category_builds_without_errors(platform):
    for username in USERNAMES:
        for category in TEXT_CATEGORIES:
            dorks = build(
                username=username, target_domain=platform.domain, category=category
            )
            assert dorks, (platform.domain, username, category)
            for dork in dorks:
                assert evaluate(
                    dork.query, exempt=(username, username.replace(" ", ""))
                ).allowed
                assert len(dork.query) <= 512
                assert dork.google_url.startswith("https://www.google.com/search?q=")


@pytest.mark.parametrize(
    ("site", "profile"),
    [
        ("instagram.com", "site:instagram.com/cristiano"),
        ("tiktok.com", "site:tiktok.com/@cristiano"),
        ("facebook.com", "site:facebook.com/cristiano"),
        (
            "snapchat.com",
            "(site:snapchat.com/add/cristiano OR site:snapchat.com/@cristiano)",
        ),
        ("x.com", "(site:x.com/cristiano OR site:twitter.com/cristiano)"),
        ("threads.net", "(site:threads.net/@cristiano OR site:threads.com/@cristiano)"),
        (
            "youtube.com",
            "(site:youtube.com/@cristiano OR site:youtube.com/c/cristiano OR site:youtube.com/user/cristiano)",
        ),
    ],
)
def test_profile_url_queries(site, profile):
    dorks = build(username="cristiano", target_domain=site)
    assert dorks[0].id == "platform_profile_url"
    assert dorks[0].query == profile


def test_instagram_query_set():
    queries = {
        d.id: d.query for d in build(username="@Leo.Messi", target_domain="instagram")
    }
    assert queries == {
        "platform_profile_url": "site:instagram.com/leo.messi",
        "platform_profile_title": 'site:instagram.com intitle:"@leo.messi"',
        "platform_handle_mention": 'site:instagram.com "@leo.messi"',
        "platform_external_links": '"instagram.com/leo.messi" -site:instagram.com',
        "public_profile_domain": 'site:instagram.com "Leo.Messi"',
    }


def test_display_name_becomes_handle_with_note():
    dorks = build(username="Cristiano Ronaldo", target_domain="instagram.com")
    assert dorks[0].query == "site:instagram.com/cristianoronaldo"
    assert any("cristianoronaldo" in w for w in dorks[0].warnings)
    assert dorks[-1].query == 'site:instagram.com "Cristiano Ronaldo"'


def test_username_without_valid_handle_falls_back_to_text():
    dorks = build(username="李明", target_domain="instagram.com")
    assert [d.id for d in dorks] == ["public_profile_domain"]
    assert any("only a text search" in w for w in dorks[0].warnings)


@pytest.mark.parametrize(
    "username", ["secret_garden", "dumps", "leaky", "tokenmaster", "password123"]
)
def test_harmless_handles_are_not_blocked(username):
    dorks = build(username=username, target_domain="instagram.com")
    assert dorks and dorks[0].query.startswith("site:instagram.com/")


def test_operators_are_still_blocked_around_usernames():
    with pytest.raises(PolicyError):
        build(
            username="alice",
            target_domain="instagram.com",
            include_phrases=["password"],
        )
    with pytest.raises(PolicyError):
        build(username="alice", target_domain="instagram.com", filetype="env")


def test_site_path_explained():
    ops = explain_operators("site:instagram.com/alice")
    assert ops[0]["explanation"].startswith("Only pages under instagram.com/alice")


def test_handle_rules():
    x = platform_for("x.com")
    assert handle_for(x, "@Elon_Musk")[0] == "Elon_Musk"
    insta = platform_for("instagram.com")
    assert handle_for(insta, "Leo-Messi!")[0] == "leomessi"
    bsky = platform_for("bsky.app")
    assert handle_for(bsky, "alice")[0] == "alice.bsky.social"


def test_open_reports_when_no_browser_launched():
    builder = DorkBuilder(opener=lambda url: False)
    dork = builder.build(DorkInput(username="alice", target_domain="instagram.com"))[0]
    url = builder.open(dork, attested=True)
    assert url == dork.google_url and builder.last_launched is False
    builder.open(dork, attested=True)  # not rate limited: nothing was opened

    def broken(url):
        raise RuntimeError("no display")

    crashing = DorkBuilder(opener=broken)
    assert crashing.open(dork, attested=True) == dork.google_url
    assert crashing.last_launched is False


def test_open_rejects_link_not_matching_query():
    builder = DorkBuilder(opener=lambda url: True)
    dork = builder.build(DorkInput(username="alice", target_domain="instagram.com"))[0]
    dork.google_url = "https://www.google.com/search?q=something+else"
    with pytest.raises(PolicyError):
        builder.open(dork, attested=True)


def test_social_site_presets_cover_all_social_platforms():
    preset_domains = {domain for _label, domain in SITE_PRESETS}
    for platform in SOCIAL_PLATFORMS:
        assert platform.domain in preset_domains


# --- TUI -----------------------------------------------------------------------


@pytest.mark.anyio
async def test_repeated_preview_does_not_crash():
    """Regression: the second 'Preview' crashed the app with DuplicateIds."""
    app_ = CveliApp()
    async with app_.run_test(size=(150, 50)) as pilot:
        await pilot.press("4")
        view = app_.query_one("#dorks")
        view.query_one("#dork_username", Input).value = "cristiano"
        for _ in range(5):
            await pilot.click("#dork_build")
            await pilot.pause()
        assert app_.is_running
        assert len(view.query(".dork-card")) == len(view.dorks) == 5
        for site in ("snapchat.com", "tiktok.com", "x.com"):
            view.query_one("#dork_site", Select).value = site
            view.query_one("#dork_build").press()
            await pilot.pause()
            assert view.dorks[0].id == "platform_profile_url"
        view.query_one("#dork_category", Select).value = "social"
        view.query_one("#dork_build").press()
        await pilot.pause()
        assert len(view.query(".dork-card")) == len(view.dorks) > 20


@pytest.mark.anyio
async def test_no_browser_copies_link_and_says_so(monkeypatch):
    monkeypatch.setattr("services.dorks.webbrowser.open", lambda url, new=2: False)
    app_ = CveliApp()
    async with app_.run_test(size=(150, 50)) as pilot:
        copied = []
        monkeypatch.setattr(app_, "copy_to_clipboard", copied.append)
        view = app_.show_view("dorks")
        view.query_one("#dork_username", Input).value = "cristiano"
        view.build()
        await pilot.pause()
        app_.research_attested = True
        view.query(".dork-open").first().press()
        await pilot.pause()
        assert copied == [view.dorks[0].google_url]
        last = list(app_._notifications)[-1].message
        assert "No browser could be started" in last
        view.query(".dork-copy-link").first().press()
        await pilot.pause()
        assert copied[-1] == view.dorks[0].google_url


@pytest.mark.anyio
async def test_cards_show_clickable_search_link():
    from textual.widgets import Link

    app_ = CveliApp()
    async with app_.run_test(size=(150, 50)) as pilot:
        view = app_.show_view("dorks")
        view.query_one("#dork_username", Input).value = "cristiano"
        view.build()
        await pilot.pause()
        links = [link.url for link in view.query(Link)]
        assert view.dorks[0].google_url in links
