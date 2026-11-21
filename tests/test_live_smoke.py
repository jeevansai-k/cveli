"""Opt-in smoke tests against real services: ``pytest -m live``.

They are excluded from the default run (see ``addopts`` in pyproject.toml) and
need outbound HTTPS to NVD, CVE.org, CISA, FIRST and GitLab.
"""

import pytest

from core.models import ExploitQuery

# pytest-httpx intercepts requests; let these tests reach the real internet.
pytestmark = [
    pytest.mark.live,
    pytest.mark.httpx_mock(should_mock=lambda request: False),
]


def test_live_cve_search_smoke():
    from services.sync import SyncService
    from storage.repositories import CVERepository

    result = SyncService().sync_sources(
        sources=["nvd", "cve_org", "epss"], query="CVE-2021-44228", limit=5
    )
    assert not result["errors"], result["errors"]
    cve = CVERepository().get_by_id("CVE-2021-44228")
    assert cve is not None and cve.cvss == 10.0 and cve.epss is not None


def test_live_kev_smoke():
    from services.sync import SyncService

    result = SyncService().sync_sources(sources=["cisa_kev"], force=True)
    assert result["sources"]["cisa_kev"] > 1000


def test_live_exploitdb_smoke():
    from services.exploitdb import ExploitDBService

    service = ExploitDBService()
    refreshed = service.refresh(force=True)
    assert refreshed.status == "updated" and refreshed.rows > 40000
    page = service.search(ExploitQuery(cve_id="CVE-2021-44228"))
    assert page.total >= 1
