"""Google Dork Builder: generation, explanations, policy, privacy, guardrails."""

import json

import pytest
from typer.testing import CliRunner

from cli.app import app
from core.dork_policy import (
    evaluate,
    validate_domain,
    validate_filetype,
    validate_username,
)
from core.dork_templates import CATEGORIES, explain_operators
from core.models import DorkInput
from services.dorks import DorkBuilder, OpenRateLimiter
from storage.research_repositories import DorkRepository
from storage.system_repositories import AuditRepository, MetricsRepository
from utils.errors import (
    AuthorizationRequiredError,
    PolicyError,
    RateLimitError,
    ValidationError,
)

runner = CliRunner()


def build(**kwargs):
    defaults = {"username": "alice", "target_domain": "example.com"}
    return DorkBuilder(opener=lambda url: True).build(
        DorkInput(**{**defaults, **kwargs})
    )


def test_schema_example_matches_spec():
    dork = build(category="profiles")[0]
    data = dork.model_dump()
    assert data["id"] == "public_profile_domain"
    assert data["label"] == "Public profile mentions"
    assert data["target_domain"] == "example.com"
    assert data["username"] == "alice"
    assert data["query"] == 'site:example.com "alice"'
    assert data["explanation"].startswith("Finds pages on example.com")
    assert data["risk_level"] == "low"
    assert data["requires_authorization"] is True
    assert data["google_url"].startswith(
        "https://www.google.com/search?q=site%3Aexample.com"
    )


@pytest.mark.parametrize("category", [c for c in CATEGORIES if c != "custom"])
def test_every_category_builds_and_passes_policy(category):
    username = "" if category in {"subdomains", "login", "directories"} else "alice"
    dorks = build(category=category, username=username)
    assert dorks
    for dork in dorks:
        assert evaluate(dork.query).allowed
        assert dork.operators, "every query must be explained"
        assert all(op.explanation for op in dork.operators)


@pytest.mark.parametrize("category", ["subdomains", "login", "directories"])
def test_infrastructure_categories_are_medium_and_warned(category):
    for dork in build(category=category, username=""):
        assert dork.risk_level == "medium"
        assert any("written authorization" in w for w in dork.warnings)


def test_example_dorks_from_spec_are_supported():
    expected = {
        'site:example.com "alice"',
        'site:example.com intitle:"alice"',
        'site:example.com filetype:pdf "alice"',
        'site:github.com "alice" "example.com"',
    }
    queries = {
        d.query for c in ("profiles", "documents", "code") for d in build(category=c)
    }
    assert expected <= queries
    linkedin = build(
        category="custom",
        target_domain="linkedin.com",
        custom_query='"example.com"',
        restrict_domain=True,
    )[0]
    assert linkedin.query == 'site:linkedin.com "example.com" "alice"'


def test_exact_match_and_filters():
    loose = build(category="profiles", exact_match=False)[0]
    assert loose.query == "site:example.com alice"
    decorated = build(
        category="documents",
        filetype="docx",
        include_phrases=["annual report"],
        exclude_phrases=["draft"],
        exclude_false_positives=True,
    )[0]
    assert "filetype:docx" in decorated.query
    assert '"annual report"' in decorated.query and '-"draft"' in decorated.query
    assert "-inurl:tag" in decorated.query


def test_operator_explanations():
    ops = explain_operators(
        'site:a.com -site:www.a.com intitle:"x y" inurl:p "z" -"q" a OR b'
    )
    kinds = [o["op"] for o in ops]
    assert kinds == ["site:", "-site:", "intitle:", "inurl:", '""', '-""', "OR"]
    assert "subdomains" in ops[0]["explanation"]


@pytest.mark.parametrize(
    "query",
    [
        'site:example.com filetype:env "DB_PASSWORD"',
        "site:example.com password",
        "site:example.com intext:passwd",
        "site:example.com api_key",
        "site:example.com API KEY",
        "site:example.com a​pi_key",
        "site:example.com ｐａｓｓｗｏｒｄ",
        '"BEGIN RSA PRIVATE KEY"',
        "site:example.com id_rsa",
        "site:example.com filetype:sql dump",
        "site:example.com ext:log",
        "site:example.com filetype:bak",
        "site:example.com breach combolist",
        "site:example.com leaked credentials",
        "site:example.com inurl:wp-config",
        "site:example.com .git",
        "site:example.com inurl:admin",
        'site:example.com intitle:"index of" backup',
        "site:example.com token",
        "cache:example.com",
    ],
)
def test_policy_blocks_secret_patterns(query):
    decision = evaluate(query)
    assert not decision.allowed
    assert decision.reason


def test_custom_query_goes_through_policy():
    with pytest.raises(PolicyError):
        build(category="custom", custom_query="filetype:env secret")
    with pytest.raises(PolicyError):
        build(category="profiles", include_phrases=["password"])


@pytest.mark.parametrize(
    "username",
    ['alice" OR site:evil.com', "site:evil.com", "a\nb", "", "x" * 65, "-alice", "a:b"],
)
def test_username_injection_rejected(username):
    with pytest.raises(ValidationError):
        validate_username(username)


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("https://www.Example.com/path?q=1", "example.com"),
        ("*.example.com", "example.com"),
        ("bücher.de", "xn--bcher-kva.de"),
    ],
)
def test_domain_normalisation(raw, clean):
    assert validate_domain(raw) == clean


@pytest.mark.parametrize(
    "raw",
    ["10.0.0.1", "localhost", "intranet.corp", "db.internal", "nodot", "-a.com", ""],
)
def test_private_or_invalid_domains_rejected(raw):
    with pytest.raises(ValidationError):
        validate_domain(raw)


def test_filetype_allowlist():
    assert validate_filetype("PDF") == "pdf"
    with pytest.raises(PolicyError):
        validate_filetype("sql")


def test_open_requires_attestation():
    builder = DorkBuilder(opener=lambda url: True)
    dork = builder.build(DorkInput(username="alice", target_domain="example.com"))[0]
    with pytest.raises(AuthorizationRequiredError):
        builder.open(dork, attested=False)


def test_open_rate_limited_and_audited():
    opened = []
    clock = [1000.0]
    limiter = OpenRateLimiter(min_interval=5, per_hour=2, clock=lambda: clock[0])
    builder = DorkBuilder(opener=opened.append, limiter=limiter)
    dork = builder.build(DorkInput(username="alice", target_domain="example.com"))[0]
    builder.open(dork, attested=True)
    with pytest.raises(RateLimitError):
        builder.open(dork, attested=True)
    clock[0] += 6
    builder.open(dork, attested=True)
    clock[0] += 6
    with pytest.raises(RateLimitError) as excinfo:
        builder.open(dork, attested=True)
    assert "Hourly limit" in str(excinfo.value)
    assert opened == [dork.google_url, dork.google_url]
    events = AuditRepository().list(event="dork_opened")
    assert len(events) == 2
    assert events[0]["object_id"] == "public_profile_domain"


def test_open_rejects_tampered_query():
    builder = DorkBuilder(opener=lambda url: True)
    dork = builder.build(DorkInput(username="alice", target_domain="example.com"))[0]
    dork.query = "site:example.com password"
    with pytest.raises(PolicyError):
        builder.open(dork, attested=True)


def test_username_not_logged_or_stored(tmp_path):
    from config.settings import get_settings
    from utils.logger import setup_root_logger

    setup_root_logger(force=True)
    builder = DorkBuilder(opener=lambda url: True)
    dork = builder.build(
        DorkInput(username="zz-hidden-handle", target_domain="unique-target.example")
    )[0]
    builder.open(dork, attested=True)
    from loguru import logger

    logger.complete()
    logs = "".join(
        p.read_text(errors="ignore") for p in get_settings().log_dir.glob("*.log")
    )
    assert "zz-hidden-handle" not in logs
    assert "unique-target.example" not in logs
    assert DorkRepository().list() == []
    audit_dump = json.dumps(AuditRepository().list())
    metrics_dump = json.dumps(MetricsRepository().summary())
    assert "zz-hidden-handle" not in audit_dump + metrics_dump
    assert "unique-target" not in audit_dump + metrics_dump


def test_explicit_save_persists_to_project():
    from services.projects import ProjectService

    dork = build(category="profiles")[0]
    ProjectService().save_dork("Case 42", dork.model_dump())
    saved = DorkRepository().list()
    assert saved[0]["username"] == "alice"
    assert ProjectService().delete("Case 42")
    assert DorkRepository().list() == []


def test_privacy_purge_removes_everything():
    from services.projects import ProjectService

    ProjectService().save_dork("Case 1", build()[0].model_dump())
    result = runner.invoke(app, ["privacy", "purge", "--yes"])
    assert result.exit_code == 0
    assert DorkRepository().list() == []


# --- CLI ----------------------------------------------------------------------


def test_cli_build_json_and_plain():
    result = runner.invoke(
        app,
        ["dork", "build", "--username", "alice", "--site", "example.com", "-f", "json"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload[0]["query"] == 'site:example.com "alice"'
    plain = runner.invoke(
        app, ["dork", "build", "-u", "alice", "-s", "example.com", "-f", "plain"]
    )
    assert plain.stdout.splitlines()[0] == 'site:example.com "alice"'


def test_cli_build_table_has_warning_and_explanations():
    result = runner.invoke(app, ["dork", "build", "-u", "alice", "-s", "github.com"])
    assert "authorized" in result.stdout
    assert "Restricts results to github.com" in result.stdout


def test_cli_blocked_query_exit_code():
    result = runner.invoke(
        app,
        ["dork", "build", "-s", "example.com", "-c", "custom", "--custom", "password"],
    )
    assert result.exit_code == 2
    assert "not allowed" in result.stdout


def test_cli_open_requires_confirmation(monkeypatch):
    opened = []
    monkeypatch.setattr(
        "services.dorks.webbrowser.open", lambda url, new=2: opened.append(url)
    )
    declined = runner.invoke(
        app,
        [
            "dork",
            "open",
            "-t",
            "public_profile_domain",
            "-u",
            "alice",
            "-s",
            "example.com",
        ],
        input="n\n",
    )
    assert declined.exit_code == 4 and opened == []
    accepted = runner.invoke(
        app,
        [
            "dork",
            "open",
            "-t",
            "public_profile_domain",
            "-u",
            "alice",
            "-s",
            "example.com",
            "--i-am-authorized",
        ],
    )
    assert accepted.exit_code == 0 and len(opened) == 1


def test_cli_feature_flag(monkeypatch):
    monkeypatch.setenv("CVELI_FEATURE_DORKS", "false")
    from config.settings import reset_settings

    reset_settings()
    assert runner.invoke(app, ["dork", "templates"]).exit_code == 3


# --- TUI ----------------------------------------------------------------------


@pytest.mark.anyio
async def test_tui_dork_preview_copy_and_attested_open(monkeypatch):
    from textual.widgets import Input

    from cli.tui.app import CveliApp
    from cli.tui.widgets import CodeBlock, ConfirmModal

    opened = []
    monkeypatch.setattr(
        "services.dorks.webbrowser.open", lambda url, new=2: opened.append(url)
    )
    app_ = CveliApp()
    async with app_.run_test(size=(150, 60)) as pilot:
        view = app_.show_view("dorks")
        view.query_one("#dork_username", Input).value = "alice"
        view.build()
        await pilot.pause()
        blocks = list(view.query(CodeBlock))
        assert blocks and blocks[0].code.startswith("site:instagram.com")
        copied = []
        monkeypatch.setattr(app_, "copy_to_clipboard", copied.append)
        blocks[0].query_one("#copy").press()
        await pilot.pause()
        assert copied == [blocks[0].code]
        view.request_open(view.dorks[0])
        await pilot.pause()
        assert isinstance(app_.screen, ConfirmModal)
        confirm = app_.screen.query_one("#confirm")
        assert confirm.disabled
        app_.screen.query_one("#attest").value = True
        await pilot.pause()
        confirm.press()
        await pilot.pause()
        assert opened and app_.research_attested


@pytest.mark.anyio
async def test_tui_blocked_input_shows_error():
    from textual.widgets import Input

    from cli.tui.app import CveliApp
    from cli.tui.widgets import EmptyState

    app_ = CveliApp()
    async with app_.run_test(size=(150, 60)) as pilot:
        view = app_.show_view("dorks")
        view.query_one("#dork_username", Input).value = 'x" OR site:evil.com'
        view.build()
        await pilot.pause()
        assert view.query(EmptyState)
        assert view.dorks == []
