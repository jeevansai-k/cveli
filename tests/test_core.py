"""
Unit Tests for Core Module.

Purpose: Test models, query parsing, validation, filters, and ranking logic.
Dependencies: pytest, core modules.
"""

import pytest

from core.filters import CVSSRangeFilter, SeverityFilter
from core.models import CVEModel
from core.ranking import rank_results
from core.search import fuzzy_match, parse_query
from core.validator import (
    ValidationError,
    sanitize_input,
    validate_cve_id,
    validate_cwe_id,
    validate_date,
    validate_severity,
)


def test_cve_model_creation():
    model = CVEModel(
        id="CVE-2024-12345",
        summary="Test vulnerability description",
        severity="High",
        cvss=8.5,
        vendor="TestVendor",
    )
    assert model.id == "CVE-2024-12345"
    assert model.severity == "High"
    assert model.cvss == 8.5
    assert model.to_dict()["id"] == "CVE-2024-12345"


def test_validator_cve_id():
    assert validate_cve_id("CVE-2024-12345") is True
    assert validate_cve_id("CVE-2021-44228") is True

    with pytest.raises(ValidationError):
        validate_cve_id("invalid-cve")


def test_validator_cwe_id():
    assert validate_cwe_id("CWE-79") is True
    assert validate_cwe_id("CWE-089") is True

    with pytest.raises(ValidationError):
        validate_cwe_id("INVALID")


def test_validator_date():
    assert validate_date("2024-08-10") is True

    with pytest.raises(ValidationError):
        validate_date("2024/08/10")


def test_validator_severity():
    assert validate_severity("Critical") is True
    assert validate_severity("high") is True

    with pytest.raises(ValidationError):
        validate_severity("SUPER_CRITICAL")


def test_sanitize_input():
    dirty = "../../etc/passwd\x00"
    safe = sanitize_input(dirty)
    assert ".." not in safe
    assert "\x00" not in safe


def test_parse_query():
    parsed = parse_query("openssl vulnerable")
    assert "openssl" in parsed["keywords"]
    assert "vulnerable" in parsed["keywords"]


def test_fuzzy_match():
    assert fuzzy_match("OpenSSL vulnerability", "openssl") > 0.8
    assert fuzzy_match("Apache Log4j", "nginx") < 0.5


def test_filters():
    cves = [
        {"id": "CVE-1", "severity": "CRITICAL", "cvss": 9.8},
        {"id": "CVE-2", "severity": "MEDIUM", "cvss": 5.5},
    ]

    crit_filter = SeverityFilter(level="CRITICAL")
    assert crit_filter.apply(cves[0]) is True
    assert crit_filter.apply(cves[1]) is False

    cvss_filter = CVSSRangeFilter(min_score=7.0)
    assert cvss_filter.apply(cves[0]) is True
    assert cvss_filter.apply(cves[1]) is False


def test_ranking():
    cves = [
        {"id": "CVE-1", "cvss": 5.0, "epss": 0.1},
        {"id": "CVE-2", "cvss": 9.8, "epss": 0.95},
    ]

    ranked_cvss = rank_results(cves, sort_by="cvss", reverse=True)
    assert ranked_cvss[0]["id"] == "CVE-2"

    ranked_epss = rank_results(cves, sort_by="epss", reverse=True)
    assert ranked_epss[0]["id"] == "CVE-2"
