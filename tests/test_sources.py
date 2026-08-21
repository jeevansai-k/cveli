"""
Unit Tests for Data Source Adapters.

Purpose: Test NVD, CVE.org, and CISA KEV adapters with mocked HTTP responses.
Dependencies: pytest, pytest-httpx, sources modules.
"""

from sources.cve_org import CVEOrgAdapter
from sources.epss import EPSSAdapter
from sources.nvd import NVDAdapter
from sources.vendor import CISAKEVAdapter


def test_nvd_adapter_normalize():
    adapter = NVDAdapter()
    sample_nvd_raw = {
        "id": "CVE-2024-12345",
        "descriptions": [{"lang": "en", "value": "Sample NVD description"}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                }
            ]
        },
        "published": "2024-08-01T12:00:00.000",
        "lastModified": "2024-08-05T12:00:00.000",
        "references": [{"url": "https://example.com/cve"}],
    }

    normalized = adapter.normalize(sample_nvd_raw)
    assert normalized["id"] == "CVE-2024-12345"
    assert normalized["severity"] == "Critical"
    assert normalized["cvss"] == 9.8
    assert normalized["summary"] == "Sample NVD description"


def test_cve_org_adapter_normalize():
    adapter = CVEOrgAdapter()
    sample_cveorg_raw = {
        "cveMetadata": {
            "cveId": "CVE-2024-54321",
            "datePublished": "2024-05-10T00:00:00Z",
        },
        "containers": {
            "cna": {
                "title": "CVE.org Test Vulnerability",
                "descriptions": [
                    {"lang": "en", "value": "Detailed CVE.org description"}
                ],
                "metrics": [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"}}],
                "affected": [{"vendor": "TestVendor", "product": "TestProduct"}],
            }
        },
    }

    normalized = adapter.normalize(sample_cveorg_raw)
    assert normalized["id"] == "CVE-2024-54321"
    assert normalized["severity"] == "High"
    assert normalized["cvss"] == 7.5


def test_cisa_kev_adapter_normalize():
    adapter = CISAKEVAdapter()
    sample_kev_item = {
        "cveID": "CVE-2024-9999",
        "vendorProject": "OpenSSL",
        "product": "OpenSSL Library",
        "shortDescription": "Buffer overflow actively exploited in wild",
        "dateAdded": "2024-01-15",
    }

    normalized = adapter.normalize(sample_kev_item)
    assert normalized["id"] == "CVE-2024-9999"
    assert normalized["exploit_available"] is True
    assert normalized["vendor"] == "OpenSSL"
    assert normalized["epss"] is None
    assert normalized["severity"] is None
    assert normalized["kev_date"] == "2024-01-15"


def test_epss_adapter_normalize_real_probability():
    normalized = EPSSAdapter().normalize(
        {"cve": "CVE-2024-9999", "epss": "0.12345", "percentile": "0.98765"}
    )
    assert normalized["id"] == "CVE-2024-9999"
    assert normalized["epss"] == 0.12345
    assert normalized["epss_percentile"] == 0.98765
    assert normalized["sources"] == ["FIRST EPSS"]
