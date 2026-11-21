"""Command-palette providers for the CVELI shell (Ctrl+P)."""

from __future__ import annotations

import re
from functools import partial

from textual.command import DiscoveryHit, Hit, Hits, Provider

CVE_RE = re.compile(r"cve-\d{4}-\d{4,7}", re.IGNORECASE)
EDB_RE = re.compile(r"(?:edb-?)(\d{1,7})", re.IGNORECASE)


class CveliCommands(Provider):
    """Navigation, theme switching, data refresh and jump-to-record."""

    def _commands(self) -> list[tuple[str, str, object]]:
        app = self.app
        commands: list[tuple[str, str, object]] = []
        for view in getattr(app, "views", []):
            commands.append(
                (
                    f"Go to {view.label}",
                    f"Open the {view.label} view",
                    partial(app.show_view, view.view_id),  # type: ignore[attr-defined]
                )
            )
        commands.extend(
            [
                (
                    "Theme: Opus 5.5 Dark",
                    "Switch to the dark theme",
                    partial(app.set_theme_preference, "dark"),  # type: ignore[attr-defined]
                ),
                (
                    "Theme: Opus 5.5 Light",
                    "Switch to the light theme",
                    partial(app.set_theme_preference, "light"),  # type: ignore[attr-defined]
                ),
                (
                    "Theme: follow terminal",
                    "Detect the terminal background",
                    partial(app.set_theme_preference, "auto"),  # type: ignore[attr-defined]
                ),
                (
                    "Refresh Exploit-DB index",
                    "Download files_exploits.csv metadata if changed",
                    partial(self._job, "exploitdb_refresh"),
                ),
                (
                    "Refresh CISA KEV + EPSS",
                    "Re-pull KEV catalogue and EPSS scores for stored CVEs",
                    partial(self._job, "cve_enrichment"),
                ),
                (
                    "New Google dork",
                    "Open the Dork Builder",
                    partial(app.show_view, "dorks"),  # type: ignore[attr-defined]
                ),
            ]
        )
        return commands

    def _job(self, name: str) -> None:
        app = self.app

        def work() -> None:
            from services.jobs import run_job

            try:
                result = run_job(name, force=True)
                app.call_from_thread(app.notify, f"{name}: {result}", timeout=5)
            except Exception as error:
                app.call_from_thread(
                    app.notify, f"{name} failed: {error}", severity="error"
                )
            app.call_from_thread(app.update_source_status)  # type: ignore[attr-defined]

        app.notify(f"Running {name}…", timeout=2)
        app.run_worker(work, thread=True, group="palette-job")

    async def discover(self) -> Hits:
        for name, help_text, callback in self._commands():
            yield DiscoveryHit(name, callback, help=help_text)  # type: ignore[arg-type]

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        cve = CVE_RE.search(query)
        if cve:
            value = cve.group(0).upper()
            yield Hit(
                100,
                f"Open {value}",
                partial(self.app.route_query, value),  # type: ignore[attr-defined]
                help="Search this CVE (live + cache)",
            )
        edb = EDB_RE.search(query)
        if edb:
            value = f"EDB-{edb.group(1)}"
            yield Hit(
                100,
                f"Open {value}",
                partial(self.app.route_query, value),  # type: ignore[attr-defined]
                help="Show this Exploit-DB entry",
            )
        for name, help_text, callback in self._commands():
            score = matcher.match(name)
            if score > 0:
                yield Hit(score, matcher.highlight(name), callback, help=help_text)  # type: ignore[arg-type]
