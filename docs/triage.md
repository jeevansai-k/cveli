# CVELI 2.0 bug triage board

Classes: **P0** crash / data loss / blocker · **P1** major function broken ·
**P2** correctness or UX · **P3** polish · **SEC** security · **A11Y** accessibility ·
**PERF** performance · **DOC** documentation.

Rule: reproduce → write a failing regression test → fix → test green.

| ID | Class | Bug | Repro | Regression test | Status |
|---|---|---|---|---|---|
| B1 | P0 | `CVERepository.save` overwrote every column; a KEV/EPSS-only record wiped CVSS, severity and dates of an existing NVD record | save NVD record, then save KEV-only record for the same ID | `tests/test_bugfixes.py::test_kev_resave_preserves_nvd_fields` | Fixed |
| B2 | P1 | `.env` never loaded; `NVD_API_KEY`, `CVELI_DB_PATH`, `CVELI_CACHE_DIR` ignored | set `NVD_API_KEY`, inspect NVD request headers | `test_foundations.py::test_settings_*`, `test_bugfixes.py::test_env_nvd_key_sent` | Fixed |
| B3 | P1 | `import config.defaults` → `ModuleNotFoundError` (package shadowed module) | `python -c "import config.defaults"` | `test_foundations.py::test_config_defaults_importable` | Fixed |
| B4 | P1 | DB/cache written inside the installed package directory | non-editable install → read-only site-packages | `test_foundations.py::test_default_database_lives_in_data_dir` | Fixed |
| B5 | P1 | `search --range` ignored for locally stored results | store 2019 CVE, `cveli search x --cache --range 1y` | `test_bugfixes.py::test_range_filters_local` | Fixed |
| B6 | P1/PERF | NVD adapter fetched only the first page per window and had no rate limiting | query with `totalResults` > page size | `test_bugfixes.py::test_nvd_paginates_until_total` | Fixed |
| B7 | PERF | Full CISA KEV catalogue downloaded and saved row-by-row on every live search; EPSS called with 1,000+ IDs | live search twice | `test_bugfixes.py::test_kev_cached_between_syncs`, `test_epss_batched` | Fixed |
| B8 | SEC | Feed text printed through Rich markup (`watchlist check`) → markup / terminal-escape injection | KEV summary containing `[bold red]` or `\x1b[2J` | `test_bugfixes.py::test_watchlist_markup_escaped`, `test_sanitize_terminal_text` | Fixed |
| B9 | SEC | Export path check was string-prefix based (`/etc`, `/var`, `..`) | `--output /usr/../etc/x` or symlink escape | `test_bugfixes.py::test_export_path_*` | Fixed |
| B10 | P2 | TUI watchlist add crashed on invalid type; `--severity` not validated | type `foo` in TUI watchlist type box | `test_bugfixes.py::test_invalid_severity_rejected`, `test_shell.py::test_watchlist_invalid_type_shows_error` | Fixed |
| B11 | P2 | `search --format table` launched the TUI when stdout was not a TTY | `cveli search x \| cat` | `test_bugfixes.py::test_search_non_tty_prints_table` | Fixed |
| B12 | P2 | `exploit_available` conflated CISA KEV with public exploits | — | `test_bugfixes.py::test_kev_and_public_exploit_flags` | Fixed |
| B13 | P3/DOC | Hard-coded version ×6, invalid `assets/textual/main.css`, dead `BaseAdapterResult`/`AsyncAdapter`/aiohttp, duplicate pytest config, doc drift | — | `test_foundations.py::test_single_version_source` | Fixed |
| B14 | P3 | `core/search`, `filters`, `ranking`, `validator` unused by commands | — | used by `services/exploitdb.py` + `search_cmd` validation | Fixed |
| B15 | P2 | Watchlist `check` re-reported the same matches forever (no "new since last check") | run `watchlist check` twice | `test_bugfixes.py::test_watchlist_reports_new_since_last_check` | Fixed |
| B16 | P2 | Search cache stored results only when `total_synced` > 0 and cache key ignored `--kev/--public-exploit` | — | `test_cli.py::test_search_cache_key_includes_range` (+ flags) | Fixed |
| B17 | P3 | `datetime.now` (local) vs UTC mixed in DB timestamps; sqlite datetime adapter deprecation | — | covered by migration tests | Fixed |
| B18 | P1 | Exact CVE-ID search hidden by the default 1-year range after the B5 fix (found in end-to-end verification); empty `--format json` printed prose instead of `[]` | `cveli search CVE-2021-44228` | `test_bugfixes.py::test_exact_cve_id_ignores_default_range` | Fixed |
