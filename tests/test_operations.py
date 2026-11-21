"""Operational commands and services: doctor, jobs, export, projects, sync, cache."""

import json
import re

import pytest
from typer.testing import CliRunner

from cli.app import app
from core.models import CVEModel, Reference
from core.safety import reference_labels
from services.jobs import JOBS, run_job
from storage.repositories import CVERepository

runner = CliRunner()


def seed(cve_id="CVE-2024-7000", **kw):
    data = {
        "id": cve_id,
        "summary": "Acme gateway overflow",
        "severity": "High",
        "cvss": 8.0,
        "published": "",
        "vendor": "acme",
        "sources": ["NVD"],
    }
    data.update(kw)
    CVERepository().save(CVEModel(**data))


def test_doctor_json_reports_schema_and_settings():
    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["version"] == "2.0.0"
    assert data["schema_version"] == data["schema_latest"]
    assert data["settings"]["nvd_api_key"] in ("set", "not set")
    table = runner.invoke(app, ["doctor"])
    assert "Settings (secrets masked)" in table.stdout


def test_jobs_list_and_cache_cleanup():
    listed = runner.invoke(app, ["jobs", "list"])
    for name in JOBS:
        assert name in listed.stdout
    result = runner.invoke(app, ["jobs", "run", "cache_cleanup", "--json"])
    assert result.exit_code == 0
    assert {"expired", "culled", "metrics_purged", "audit_purged"} <= set(
        json.loads(result.stdout)
    )
    assert runner.invoke(app, ["jobs", "run", "nope"]).exit_code != 0
    with pytest.raises(KeyError):
        run_job("nope")


def test_cve_enrichment_job(httpx_mock):
    seed()
    httpx_mock.add_response(
        url=re.compile(r".*known_exploited.*"),
        json={
            "vulnerabilities": [{"cveID": "CVE-2024-7000", "dateAdded": "2024-05-01"}]
        },
    )
    httpx_mock.add_response(
        url=re.compile(r".*api\.first\.org.*"),
        json={"data": [{"cve": "CVE-2024-7000", "epss": "0.3", "percentile": "0.8"}]},
    )
    result = run_job("cve_enrichment", force=True)
    assert result["kev_records"] == 1 and result["epss_updated"] == 1
    stored = CVERepository().get_by_id("CVE-2024-7000")
    assert stored.kev and stored.epss == 0.3 and stored.cvss == 8.0


def test_index_rebuild_job():
    result = run_job("index_rebuild")
    assert "cve_counts_updated" in result


def test_export_command_formats(tmp_path):
    seed()
    for fmt, suffix in (
        ("json", "json"),
        ("csv", "csv"),
        ("markdown", "md"),
        ("txt", "txt"),
    ):
        out = tmp_path / f"r.{suffix}"
        result = runner.invoke(
            app, ["export", "acme", "-o", str(out), "-f", fmt, "--offline"]
        )
        assert result.exit_code == 0, result.output
        assert out.read_text()
    assert json.loads((tmp_path / "r.json").read_text())[0]["id"] == "CVE-2024-7000"
    assert "CVSS 8.0" in (tmp_path / "r.txt").read_text()


def test_export_command_errors(tmp_path):
    seed()
    none = runner.invoke(
        app, ["export", "zzz", "-o", str(tmp_path / "x.json"), "--offline"]
    )
    assert none.exit_code == 1
    bad = runner.invoke(app, ["export", "acme", "-o", "/etc/cveli.json", "--offline"])
    assert bad.exit_code == 2 and "system directory" in bad.stdout
    sev = runner.invoke(app, ["export", "-o", "x.json", "--severity", "bogus"])
    assert sev.exit_code != 0


def test_project_cli_lifecycle():
    seed()
    assert runner.invoke(app, ["project", "create", "Case A"]).exit_code == 0
    assert runner.invoke(app, ["project", "create", "Case A"]).exit_code == 2
    assert (
        runner.invoke(
            app, ["project", "add", "Case A", "cve", "cve-2024-7000"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(app, ["project", "add", "Case A", "exploit", "EDB-123"]).exit_code
        == 0
    )
    assert runner.invoke(app, ["project", "add", "Case A", "cve", "bad"]).exit_code == 2
    shown = json.loads(
        runner.invoke(app, ["project", "show", "Case A", "-f", "json"]).stdout
    )
    assert [i["ref_id"] for i in shown["items"]] == ["CVE-2024-7000", "123"]
    listing = runner.invoke(app, ["project", "list"])
    assert "Case A" in listing.stdout
    assert runner.invoke(app, ["project", "delete", "Case A", "--yes"]).exit_code == 0
    assert runner.invoke(app, ["project", "delete", "Case A", "--yes"]).exit_code == 1


def test_sync_command_reports_sources_and_errors(httpx_mock, no_sleep):
    httpx_mock.add_response(
        url=re.compile(r".*known_exploited.*"),
        json={"vulnerabilities": [{"cveID": "CVE-2024-1", "dateAdded": "2024-01-01"}]},
    )
    ok = runner.invoke(app, ["sync", "--source", "cisa_kev"])
    assert ok.exit_code == 0 and "cisa_kev: 1 fetched" in ok.stdout
    again = runner.invoke(app, ["sync", "--source", "cisa_kev"])
    assert "still fresh" in again.stdout
    for _ in range(4):
        httpx_mock.add_response(url=re.compile(r".*nvd.*"), status_code=503)
    failed = runner.invoke(app, ["sync", "--source", "nvd", "-q", "x"])
    assert failed.exit_code == 1 and "nvd failed" in failed.stdout
    assert runner.invoke(app, ["sync", "--source", "bogus"]).exit_code != 0


def test_cache_and_privacy_and_settings_commands():
    assert runner.invoke(app, ["cache", "status", "--json"]).exit_code == 0
    assert runner.invoke(app, ["cache", "clear"]).exit_code == 0
    assert runner.invoke(app, ["cache", "cleanup"]).exit_code == 0
    assert "privacy notice" in runner.invoke(app, ["privacy", "notice"]).stdout.lower()
    shown = json.loads(runner.invoke(app, ["settings", "show", "--json"]).stdout)
    assert shown["feature_exploitdb"] == "True"
    assert runner.invoke(app, ["settings", "motion", "--reduce"]).exit_code == 0


def test_stats_command_shows_kev_and_exploits():
    seed(kev=True, kev_date="2024-01-01", tags=["cisa_kev"])
    result = runner.invoke(app, ["stats"])
    assert "CISA KEV" in result.stdout and "Exploit-DB entries" in result.stdout


def test_reference_labels():
    assert reference_labels(Reference(url="https://p", tags=["Patch"])) == [
        "Patch reference"
    ]
    assert "Proof-of-concept reference" in reference_labels(
        Reference(url="https://e", tags=["Exploit"])
    )
    assert reference_labels(Reference(url="https://x")) == ["Informational"]


def test_no_tty_root_command_prints_help():
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "Usage" in result.stdout
