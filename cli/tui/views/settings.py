"""Settings view: theme, motion, data management, paths and privacy."""

from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, RadioButton, RadioSet, Static, Switch

from cli.tui.views.base import View
from config.settings import get_settings
from core.safety import AUTHORIZED_USE_DISCLAIMER


class SettingsView(View):
    view_id = "settings"
    label = "Settings"
    icon = "⚙"

    def compose(self) -> ComposeResult:
        from storage.system_repositories import SettingsRepository

        saved = SettingsRepository().get("theme", "auto")
        yield Static("Settings", classes="view-title")
        yield Static("Appearance", classes="section-title")
        with RadioSet(id="theme_choice"):
            yield RadioButton("Dark", value=saved == "dark", id="theme_dark")
            yield RadioButton("Light", value=saved == "light", id="theme_light")
            yield RadioButton(
                "Follow terminal (auto)",
                value=saved not in ("dark", "light"),
                id="theme_auto",
            )
        with Horizontal(classes="form-row"):
            yield Static("Reduce motion", classes="label")
            yield Switch(value=self._reduce_motion(), id="reduce_motion")
        yield Static("Data", classes="section-title")
        with Horizontal(classes="form-row"):
            yield Button("Refresh CISA KEV", id="refresh_kev")
            yield Button("Clean cache", id="cleanup_cache")
        yield Static("", id="data_status", classes="muted", markup=False)
        yield Static("Privacy", classes="section-title")
        yield Static(
            "Usernames, domains and dorks are kept in memory only and are never "
            "logged. They are stored only when you save them to a project. "
            "Audit entries record event types, never your inputs.",
            classes="muted",
        )
        with Horizontal(classes="form-row"):
            yield Button(
                "Purge saved research data", id="privacy_purge", variant="error"
            )
        yield Static("Paths & features", classes="section-title")
        yield Static(self._paths_text(), classes="muted", markup=False)
        yield Static(AUTHORIZED_USE_DISCLAIMER, classes="muted")

    @staticmethod
    def _reduce_motion() -> bool:
        from storage.system_repositories import SettingsRepository

        return bool(
            get_settings().reduce_motion or SettingsRepository().get("reduce_motion")
        )

    @staticmethod
    def _paths_text() -> str:
        s = get_settings()
        flags = ", ".join(
            f"{name}={'on' if getattr(s, f'feature_{name}') else 'off'}"
            for name in ("exploitdb", "dorks", "msf")
        )
        return (
            f"Database: {s.db_path}\nCache: {s.cache_dir}\nLogs: {s.log_dir}\n"
            f"NVD API key: {'set' if s.nvd_api_key else 'not set'}\nFeatures: {flags}"
        )

    @on(RadioSet.Changed, "#theme_choice")
    def _theme(self, event: RadioSet.Changed) -> None:
        choice = {"theme_dark": "dark", "theme_light": "light"}.get(
            event.pressed.id or "", "auto"
        )
        self.app.set_theme_preference(choice)  # type: ignore[attr-defined]

    @on(Switch.Changed, "#reduce_motion")
    def _motion(self, event: Switch.Changed) -> None:
        from storage.system_repositories import SettingsRepository

        SettingsRepository().set("reduce_motion", bool(event.value))
        self.app.animation_level = "none" if event.value else "full"

    @on(Button.Pressed, "#refresh_kev")
    def _refresh_kev(self) -> None:
        self.query_one("#data_status", Static).update("Refreshing CISA KEV…")
        self._run_job("cve_enrichment")

    @on(Button.Pressed, "#cleanup_cache")
    def _cleanup(self) -> None:
        self._run_job("cache_cleanup")

    def _run_job(self, name: str) -> None:
        def work() -> None:
            from services.jobs import run_job

            try:
                result = run_job(name, force=True)
                message = f"{name}: {result}"
            except Exception as error:
                message = f"{name} failed: {error}"
            self.app.call_from_thread(
                self.query_one("#data_status", Static).update, message
            )

        self.run_worker(work, thread=True, exclusive=True, group="settings-job")

    @on(Button.Pressed, "#privacy_purge")
    def _purge(self) -> None:
        from cli.tui.widgets import ConfirmModal

        def done(confirmed: bool | None) -> None:
            if confirmed:
                from services.projects import ProjectService

                removed = ProjectService().purge_all()
                self.app.notify(f"Purged {removed} saved research item(s).")

        self.app.push_screen(
            ConfirmModal(
                "Purge saved research data",
                "Deletes all projects, saved dorks, saved searches, generated "
                "report records and the audit log. This cannot be undone.",
                "I understand this permanently deletes my saved research data.",
            ),
            done,
        )
