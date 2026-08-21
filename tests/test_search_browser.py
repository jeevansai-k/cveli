import pytest
from textual.widgets import Link

from cli.tui.search_browser import (
    DetailScreen,
    PagedResults,
    SearchBrowserApp,
    SearchResultsScreen,
    resolve_page_selection,
)
from core.formatter import build_reference_items, is_safe_reference_url
from core.models import CVEModel


def make_results(count: int) -> list[CVEModel]:
    return [
        CVEModel(
            id=f"CVE-2024-{10000 + index}",
            summary=f"Summary {index}",
            severity="High" if index % 2 else "Medium",
            cvss=8.0 if index % 2 else 5.0,
            vendor="Vendor",
            published="2024-08-01",
            references=["https://vendor.example/advisory"],
        )
        for index in range(count)
    ]


def test_max_page_size_is_25():
    pager = PagedResults(make_results(60))
    assert pager.page_size == 25
    assert len(pager.page_items()) == 25


@pytest.mark.parametrize("count", [0, 1, 2, 25, 26, 50, 51])
def test_paged_results_support_all_counts(count):
    pager = PagedResults(make_results(count))
    assert pager.total_results == count
    assert pager.total_pages >= 1


@pytest.mark.parametrize(("count", "pages"), [(25, 1), (26, 2), (50, 2), (51, 3)])
def test_total_pages(count, pages):
    assert PagedResults(make_results(count)).total_pages == pages


def test_serial_numbers_are_global_across_pages():
    pager = PagedResults(make_results(60))
    assert pager.page_serials() == list(range(1, 26))
    pager.next_page()
    assert pager.page_serials() == list(range(26, 51))


def test_global_selection_maps_to_result():
    pager = PagedResults(make_results(30))
    pager.next_page()
    assert pager.select(26).id == "CVE-2024-10025"
    assert pager.select(30).id == "CVE-2024-10029"


def test_resolve_page_selection():
    assert resolve_page_selection("26", 26, 50) == 26
    assert resolve_page_selection("q", 26, 50) is None
    with pytest.raises(ValueError):
        resolve_page_selection("1", 26, 50)


def test_safe_url_validation():
    assert is_safe_reference_url("https://example.com")
    assert is_safe_reference_url("http://example.com")
    assert not is_safe_reference_url("javascript:alert(1)")
    assert not is_safe_reference_url("file:///tmp/test")
    assert not is_safe_reference_url("ssh://example.com")


def test_build_reference_items_rejects_unsafe_urls():
    items = build_reference_items(
        CVEModel(
            id="CVE-2024-77777",
            summary="x",
            references=[
                "https://safe.example/ref",
                "javascript:alert(1)",
                "file:///tmp/nope",
            ],
        )
    )
    urls = [url for _, url in items]
    assert "https://safe.example/ref" in urls
    assert "javascript:alert(1)" not in urls
    assert "file:///tmp/nope" not in urls


def test_build_reference_items_extracts_multiple_urls_from_reference():
    items = build_reference_items(
        CVEModel(
            id="CVE-2024-77778",
            summary="x",
            references=[
                "https://vendor.example/advisory ; https://nvd.nist.gov/vuln/detail/CVE-2024-77778"
            ],
        )
    )
    urls = [url for _, url in items]
    assert "https://vendor.example/advisory" in urls
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-77778" in urls


@pytest.mark.anyio
async def test_alt_navigation_and_boundaries():
    app = SearchBrowserApp(make_results(51))
    async with app.run_test() as pilot:
        assert isinstance(app.screen, SearchResultsScreen)
        assert app.pager.current_page == 0
        await pilot.press("alt+left")
        assert app.pager.current_page == 0
        await pilot.press("alt+right")
        assert app.pager.current_page == 1
        await pilot.press("alt+right")
        assert app.pager.current_page == 2
        await pilot.press("alt+right")
        assert app.pager.current_page == 2
        await pilot.press("alt+left")
        assert app.pager.current_page == 1


@pytest.mark.anyio
async def test_selecting_cve_opens_correct_detail_view():
    app = SearchBrowserApp(make_results(30))
    async with app.run_test() as pilot:
        assert isinstance(app.screen, SearchResultsScreen)
        await pilot.press("2", "enter")
        assert isinstance(app.screen, DetailScreen)
        assert app.screen.cve.id == "CVE-2024-10001"


@pytest.mark.anyio
async def test_back_returns_to_same_page():
    app = SearchBrowserApp(make_results(30))
    async with app.run_test() as pilot:
        await pilot.press("alt+right")
        assert app.pager.current_page == 1
        await pilot.press("2", "6", "enter")
        assert isinstance(app.screen, DetailScreen)
        assert app.screen.cve.id == "CVE-2024-10025"
        await pilot.press("enter")
        assert isinstance(app.screen, SearchResultsScreen)
        assert app.pager.current_page == 1


@pytest.mark.anyio
async def test_escape_returns_from_detail_to_results():
    app = SearchBrowserApp(make_results(30))
    async with app.run_test() as pilot:
        await pilot.press("alt+right")
        await pilot.press("2", "6", "enter")
        assert isinstance(app.screen, DetailScreen)
        await pilot.press("escape")
        assert isinstance(app.screen, SearchResultsScreen)
        assert app.pager.current_page == 1


@pytest.mark.anyio
async def test_highlighted_row_enter_opens_selected_cve():
    app = SearchBrowserApp(make_results(30))
    async with app.run_test() as pilot:
        await pilot.press("down", "enter")
        assert isinstance(app.screen, DetailScreen)
        assert app.screen.cve.id == "CVE-2024-10001"


@pytest.mark.anyio
async def test_global_serial_selection_on_second_page():
    app = SearchBrowserApp(make_results(30))
    async with app.run_test() as pilot:
        await pilot.press("alt+right")
        await pilot.press("3", "0", "enter")
        assert isinstance(app.screen, DetailScreen)
        assert app.screen.cve.id == "CVE-2024-10029"


@pytest.mark.anyio
async def test_page_displays_global_serials():
    app = SearchBrowserApp(make_results(51))
    async with app.run_test() as pilot:
        table = app.screen.query_one("#results_table")
        assert str(table.get_row_at(0)[0]) == "1"
        await pilot.press("alt+right")
        table = app.screen.query_one("#results_table")
        assert str(table.get_row_at(0)[0]) == "26"


@pytest.mark.anyio
async def test_q_exits_results_screen():
    app = SearchBrowserApp(make_results(1))
    async with app.run_test() as pilot:
        await pilot.press("q")
        await pilot.pause()
        assert app.is_running is False


@pytest.mark.anyio
async def test_q_exits_detail_screen():
    app = SearchBrowserApp(make_results(1))
    async with app.run_test() as pilot:
        await pilot.press("enter")
        assert isinstance(app.screen, DetailScreen)
        await pilot.press("q")
        await pilot.pause()
        assert app.is_running is False
        assert app.return_to_main_menu is True


@pytest.mark.anyio
async def test_detail_links_are_clickable():
    app = SearchBrowserApp(
        [
            CVEModel(
                id="CVE-2024-88888",
                summary="Clickable links",
                references=["https://vendor.example/advisory"],
                exploit_available=True,
                tags=["cisa_kev"],
            )
        ]
    )
    opened: list[str] = []

    async with app.run_test() as pilot:
        await pilot.press("1", "enter")
        assert isinstance(app.screen, DetailScreen)
        app._driver.open_url = lambda url, new_tab=True: opened.append(url)  # type: ignore[assignment]
        app.screen.query_one(Link).action_open_link()
        await pilot.pause()
        assert opened
        assert opened[0] == "https://nvd.nist.gov/vuln/detail/CVE-2024-88888"


@pytest.mark.anyio
async def test_search_source_note_is_visible():
    app = SearchBrowserApp(make_results(1), source_note="Source: CACHE | Updated: now")
    async with app.run_test():
        assert "Source: CACHE" in str(app.screen.query_one("#source_note").render())


@pytest.mark.anyio
async def test_cve_screens_do_not_show_main_branding():
    app = SearchBrowserApp(make_results(1))
    async with app.run_test() as pilot:
        assert "CVELI" not in str(app.screen.query_one("#search_title").render())
        await pilot.press("enter")
        assert isinstance(app.screen, DetailScreen)
        assert not list(app.screen.query(".brand"))


@pytest.mark.anyio
async def test_missing_optional_fields_do_not_crash():
    app = SearchBrowserApp([CVEModel(id="CVE-2024-99999", summary="Minimal")])
    async with app.run_test() as pilot:
        await pilot.press("1", "enter")
        assert isinstance(app.screen, DetailScreen)


@pytest.mark.anyio
async def test_zero_results_show_empty_state_and_exit():
    app = SearchBrowserApp([])
    async with app.run_test() as pilot:
        assert isinstance(app.screen, SearchResultsScreen)
        empty_state = app.screen.query_one("#empty_state")
        table = app.screen.query_one("#results_table")
        assert empty_state.display is True
        assert table.display is False
        await pilot.press("enter")
