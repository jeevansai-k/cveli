"""Metasploit research-template generator: structure, safety, escaping, export."""

import json
import re
import shutil
import subprocess

import pytest
from typer.testing import CliRunner

from cli.app import app
from core.models import CVEModel, ExploitModel
from core.msf import FORBIDDEN_PRIMITIVES, PREFLIGHT_CHECKLIST, TemplateContext
from core.msf.escape import ruby_q_block, ruby_single, safe_reference_url
from core.msf.render import render_ruby
from services.msf_template import MsfTemplateService, assert_safe, code_only
from storage.exploit_repository import ExploitRepository
from storage.repositories import CVERepository
from storage.research_repositories import ReportRepository
from storage.system_repositories import AuditRepository
from utils.errors import AuthorizationRequiredError, PolicyError, ValidationError

runner = CliRunner()
HOSTILE = (
    "Overflow '); system('rm -rf /'); #{`id`} } end\nclass Evil; end "
    "\x1b[31m%q{ payload.encoded } \\' eval(x)"
)


def exploit(edb_id=50592, type_="remote", port=None, **kw):
    data = {
        "edb_id": edb_id,
        "title": "Acme Server 1.2 - Remote Code Execution",
        "cve_ids": ["CVE-2024-90001"],
        "date_published": "2024-02-02",
        "platform": "linux",
        "type": type_,
        "port": port,
        "verified": True,
        "source_url": f"https://www.exploit-db.com/exploits/{edb_id}",
        "affected_product": "Acme Server",
        "affected_versions": ["1.2"],
        "safety_labels": ["Research only"],
    }
    data.update(kw)
    return ExploitModel(**data)


@pytest.fixture
def seeded():
    CVERepository().save(
        CVEModel(
            id="CVE-2024-90001",
            summary="Acme Server before 1.3 allows remote code execution.",
            severity="Critical",
            cvss=9.8,
            published="2024-01-15",
            references=["https://acme.example/advisory"],
            affected_products=[{"name": "acme/server", "version": "1.2"}],
            sources=["NVD"],
        )
    )
    ExploitRepository().replace_all(
        [
            exploit(50592, "webapps", 8080),
            exploit(50600, "local", title="Acme Agent 2.0 - LPE", cve_ids=[]),
            exploit(50601, "dos", title="Acme Server 1.2 - DoS", cve_ids=[]),
            exploit(50602, "remote", 4444, title="Acme Daemon - Overflow", cve_ids=[]),
        ]
    )
    return MsfTemplateService()


@pytest.mark.parametrize(
    ("kwargs", "module_type", "superclass", "mixin", "method"),
    [
        (
            {"cve_id": "CVE-2024-90001"},
            "exploit",
            "Msf::Exploit::Remote",
            "Msf::Exploit::Remote::HttpClient",
            "exploit",
        ),
        ({"edb_id": 50600}, "exploit", "Msf::Exploit::Local", None, "exploit"),
        (
            {"edb_id": 50601},
            "auxiliary",
            "Msf::Auxiliary",
            "Msf::Exploit::Remote::HttpClient",
            "run",
        ),
        (
            {"edb_id": 50602},
            "exploit",
            "Msf::Exploit::Remote",
            "Msf::Exploit::Remote::Tcp",
            "exploit",
        ),
        (
            {"cve_id": "CVE-2024-90001", "module_type": "post"},
            "post",
            "Msf::Post",
            None,
            "run",
        ),
        (
            {"cve_id": "CVE-2024-90001", "module_type": "auxiliary"},
            "auxiliary",
            "Msf::Auxiliary",
            "Msf::Exploit::Remote::HttpClient",
            "run",
        ),
    ],
)
def test_module_types_and_structure(
    seeded, kwargs, module_type, superclass, mixin, method
):
    bundle = seeded.generate(live=False, **kwargs)
    ruby = bundle.ruby
    assert bundle.module_type == module_type
    assert f"class MetasploitModule < {superclass}" in ruby
    if mixin:
        assert f"include {mixin}" in ruby
    for field in (
        "'Name' =>",
        "'Description' =>",
        "'Author' =>",
        "'License' => MSF_LICENSE",
        "'References' =>",
        "'Notes' =>",
    ):
        assert field in ruby
    assert "def check" in ruby and "CheckCode::Unknown" in ruby
    assert f"def {method}" in ruby
    assert "def validate_target" in ruby
    assert (
        "fail_with(Failure::NoTarget, 'Target validation and authorization are required.')"
        in ruby
    )
    for todo in (
        "TODO(authorization)",
        "TODO(target-validation)",
        "TODO(payload-selection)",
        "TODO(safe-testing)",
        "TODO(authentication)",
    ):
        assert todo in ruby
    for item in PREFLIGHT_CHECKLIST:
        assert item in ruby
    assert "RESEARCH TEMPLATE ONLY" in ruby


def test_metadata_references_and_dates(seeded):
    bundle = seeded.generate(cve_id="CVE-2024-90001", live=False)
    assert "['CVE', '2024-90001']" in bundle.ruby
    assert "['EDB', '50592']" in bundle.ruby
    assert "['URL', 'https://acme.example/advisory']" in bundle.ruby
    assert "'DisclosureDate' => '2024-01-15'" in bundle.ruby
    meta = bundle.metadata
    assert meta["cve_id"] == "CVE-2024-90001"
    assert meta["edb_ids"] == [50592]
    assert meta["affected_product"] == "acme/server"
    assert meta["affected_versions"] == ["1.2"]
    assert meta["safety"]["contains_payload"] is False
    assert meta["preflight_checklist"] == PREFLIGHT_CHECKLIST
    assert "Research report: CVE-2024-90001" in bundle.markdown
    assert "- [ ] Written authorization" in bundle.markdown


def test_edb_only_uses_exploit_product(seeded):
    bundle = seeded.generate(edb_id=50592, live=False)
    assert "# Product:  Acme Server" in bundle.ruby
    assert bundle.cve_id == "CVE-2024-90001"


@pytest.mark.parametrize("module_type", ["auto", "exploit", "auxiliary", "post"])
def test_no_payload_primitives(seeded, module_type):
    bundle = seeded.generate(
        cve_id="CVE-2024-90001", module_type=module_type, live=False
    )
    code = code_only(bundle.ruby)
    for primitive in FORBIDDEN_PRIMITIVES:
        assert primitive.lower() not in code.lower(), primitive
    assert "payload" not in code.lower().replace("payload-selection", "")
    assert "send_request" not in bundle.ruby


def test_assert_safe_blocks_injected_code():
    with pytest.raises(PolicyError):
        assert_safe("def exploit\n  sock.put(payload.encoded)\nend\n")
    assert_safe("# mentions sock.put in a comment\nx = 'eval(1)'\n")


def test_hostile_summary_escaped():
    context = TemplateContext(
        cve=CVEModel(id="CVE-2024-1", summary=HOSTILE, published="2024-01-01"),
        exploits=[exploit(title=HOSTILE, author=HOSTILE)],
        author="Mallory'); system('x'); #",
    )
    ruby, _, _ = render_ruby(context)
    assert_safe(ruby)
    description = ruby.split("%q{", 1)[1].split("\n        },", 1)[0]
    assert "}" not in description and "\\" not in description
    assert "\x1b" not in ruby
    assert re.search(r"'Author' => \[\n\s+'Mallory\\'\); system\(\\'x\\'\); #'", ruby)
    assert "\nclass Evil" not in ruby


def test_escape_helpers():
    assert ruby_single("a'b\\c") == "a\\'b\\\\c"
    assert "}" not in ruby_q_block("x } y { z")
    assert safe_reference_url("javascript:alert(1)") is None
    assert safe_reference_url("https://x.example/a'b") is None
    assert safe_reference_url("https://ok.example/p?q=1") == "https://ok.example/p?q=1"


@pytest.mark.skipif(shutil.which("ruby") is None, reason="ruby not installed")
@pytest.mark.parametrize("module_type", ["auto", "exploit", "auxiliary", "post"])
def test_ruby_syntax(seeded, tmp_path, module_type):
    for kwargs in ({"cve_id": "CVE-2024-90001"}, {"edb_id": 50600}, {"edb_id": 50602}):
        bundle = seeded.generate(module_type=module_type, live=False, **kwargs)
        path = tmp_path / f"{bundle.id}_{module_type}.rb"
        path.write_text(bundle.ruby)
        result = subprocess.run(
            ["ruby", "-c", str(path)], capture_output=True, text=True, check=False
        )
        assert result.returncode == 0, result.stderr


@pytest.mark.skipif(shutil.which("ruby") is None, reason="ruby not installed")
def test_ruby_syntax_hostile(tmp_path):
    context = TemplateContext(
        cve=CVEModel(id="CVE-2024-1", summary=HOSTILE),
        exploits=[exploit(title=HOSTILE)],
        author=HOSTILE,
    )
    ruby, _, _ = render_ruby(context)
    path = tmp_path / "hostile.rb"
    path.write_text(ruby)
    result = subprocess.run(["ruby", "-c", str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_export_requires_confirmation(seeded, tmp_path):
    bundle = seeded.generate(cve_id="CVE-2024-90001", live=False)
    with pytest.raises(AuthorizationRequiredError):
        seeded.export(bundle, str(tmp_path / "out"))
    assert not (tmp_path / "out").exists()


def test_export_writes_formats_and_audits(seeded, tmp_path):
    bundle = seeded.generate(cve_id="CVE-2024-90001", live=False)
    paths = seeded.export(
        bundle, str(tmp_path / "out"), confirmed=True, project="Case 7"
    )
    assert sorted(p.rsplit(".", 1)[1] for p in paths) == ["json", "md", "rb"]
    meta = json.loads((tmp_path / "out" / f"{bundle.id}.json").read_text())
    assert meta["schema"] == "cveli.msf-template/1"
    assert ReportRepository().list()[0]["cve_id"] == "CVE-2024-90001"
    event = AuditRepository().list(event="template_exported")[0]
    assert event["details"]["module_type"] == "exploit"
    from services.projects import ProjectService

    items = ProjectService().show("Case 7")["items"]
    assert items[0]["kind"] == "report"


def test_export_rejects_bad_format_and_path(seeded):
    bundle = seeded.generate(cve_id="CVE-2024-90001", live=False)
    with pytest.raises(ValidationError):
        seeded.export(bundle, "/tmp", formats=["exe"], confirmed=True)
    with pytest.raises(ValidationError):
        seeded.export(bundle, "/etc/cveli", confirmed=True)


def test_unknown_inputs(seeded):
    with pytest.raises(ValidationError):
        seeded.generate(edb_id=999999, live=False)
    with pytest.raises(ValidationError):
        seeded.generate(cve_id="CVE-2099-0001", live=False)
    with pytest.raises(ValidationError):
        seeded.generate(cve_id="not-a-cve", live=False)
    with pytest.raises(ValidationError):
        seeded.generate(cve_id="CVE-2024-90001", module_type="payload", live=False)


# --- CLI ----------------------------------------------------------------------


def test_cli_preview_does_not_write(seeded, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app, ["msf", "generate", "--cve", "CVE-2024-90001", "--offline"]
    )
    assert result.exit_code == 0
    assert "MetasploitModule" in result.stdout
    assert not list(tmp_path.rglob("*.rb"))


def test_cli_export_prompts_and_declines(seeded, tmp_path):
    result = runner.invoke(
        app,
        [
            "msf",
            "generate",
            "--cve",
            "CVE-2024-90001",
            "--offline",
            "--out",
            str(tmp_path / "out"),
        ],
        input="n\n",
    )
    assert result.exit_code == 4
    assert "Preflight checklist" in result.stdout
    assert not (tmp_path / "out").exists()


def test_cli_export_confirmed_json(seeded, tmp_path):
    result = runner.invoke(
        app,
        [
            "msf",
            "generate",
            "--edb",
            "EDB-50592",
            "--offline",
            "--out",
            str(tmp_path),
            "--confirm-research",
            "--formats",
            "rb,json",
            "-f",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert len(payload["files"]) == 2
    assert payload["module_type"] == "exploit"


def test_cli_feature_flag(monkeypatch):
    monkeypatch.setenv("CVELI_FEATURE_MSF", "0")
    from config.settings import reset_settings

    reset_settings()
    assert runner.invoke(app, ["msf", "generate", "--cve", "CVE-2024-1"]).exit_code == 3


# --- TUI ----------------------------------------------------------------------


@pytest.mark.anyio
async def test_tui_template_review_and_confirmed_export(seeded, tmp_path):
    from textual.widgets import Input

    from cli.tui.app import CveliApp
    from cli.tui.views.templates import TemplatePreview
    from cli.tui.widgets import ConfirmModal

    app_ = CveliApp()
    async with app_.run_test(size=(160, 60)) as pilot:
        view = app_.show_view("templates")
        view.query_one("#tpl_cve", Input).value = "CVE-2024-90001"
        view.generate()
        await app_.workers.wait_for_complete()
        await pilot.pause()
        preview = view.query_one(TemplatePreview)
        assert "MetasploitModule" in preview.bundle.ruby
        preview.query_one("#tpl_out", Input).value = str(tmp_path / "tui")
        preview.request_export()
        await pilot.pause()
        assert isinstance(app_.screen, ConfirmModal)
        app_.screen.query_one("#attest").value = True
        await pilot.pause()
        app_.screen.query_one("#confirm").press()
        await pilot.pause()
        assert len(list((tmp_path / "tui").iterdir())) == 3


@pytest.mark.anyio
async def test_detail_screen_m_opens_template(seeded):
    from cli.tui.search_browser import SearchBrowserApp
    from cli.tui.views.templates import TemplateScreen

    cve = CVERepository().get_by_id("CVE-2024-90001")
    app_ = SearchBrowserApp([cve])
    async with app_.run_test(size=(160, 60)) as pilot:
        await pilot.press("1", "enter")
        await pilot.press("m")
        await pilot.pause()
        assert isinstance(app_.screen, TemplateScreen)
