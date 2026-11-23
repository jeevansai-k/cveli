# Changelog

## Unreleased

Project website and launch video:

- New landing page in `site/` (Dark/Light, responsive), published with GitHub Pages.
- 20-second launch video (`site/assets/cveli-launch.mp4`) built from real TUI captures.
- New app icon (`site/assets/icon.svg`) and a rewritten README with the video, gallery and architecture.

Dork Builder reliability for social media:

- Fixed: pressing **Preview** a second time crashed the TUI (`DuplicateIds`).
- Fixed: "Opened in your browser" was shown even when no browser could be
  launched; CVELI now copies the link to the clipboard and says so (the CLI
  prints the link).
- Social profiles now use Google's URL-prefix form (`site:instagram.com/<user>`,
  `site:snapchat.com/add/<user>`, `site:tiktok.com/@<user>`) plus title, mention
  and "sites linking to the profile" queries — far more precise than the old
  `inurl:` matching.
- Per-platform handle rules: display names and invalid characters are converted
  to a valid handle (with a note); Bluesky handles get `.bsky.social`; Threads
  covers threads.net and threads.com.
- Usernames are no longer falsely blocked by the safety policy (e.g.
  `secret_garden`, `dumps`); operators, file types and phrases are still checked.
- Every result card has a clickable search link and a *Copy link* button.
- Verified with a sweep of ~24,000 generated queries across all platforms,
  categories and tricky usernames (no errors).

Earlier fixes from user testing of 2.0.0:

Fixes from user testing of 2.0.0:

- **Add to project** now asks which project to use: pick any existing project or
  create a new one (CVE detail `P`, CVE search list `P`, Exploit-DB detail, Dork
  Builder "Save to project"). Previously everything went to a "Default research"
  project.
- The research-only **export confirmation** now lets you choose the file types to
  write (`.rb`, `.md`, `.json`); at least one must be selected.
- **Watchlist**: new *Remove selected* button (with confirmation); the Delete key
  also works.
- **Themes** are now named **Dark** and **Light** everywhere (settings, toasts,
  command palette, `cveli settings theme`). Textual's built-in themes are hidden
  from the theme picker.
- **Dork Builder**: 20 social networks added to the site list; new *Social media
  accounts* category that searches all of them without a target site; platform
  profile-URL queries (e.g. `snapchat.com/add/<user>`) so Snapchat and other
  social usernames are found; `@handles`, platform names (`snapchat`, `twitter`)
  and profile URLs are accepted as input.
- The palette's **Keys** guide shows "To close this page select [keys] from
  palette again".
- **Borders and scrollbars**: replaced half-block "tall" borders and 2-column
  scrollbars (which rendered with a sideways wobble in many fonts) with box-drawing
  borders and solid 1-column scrollbars; focus changes colour only, so nothing
  shifts.

## 2.0.0 — 2026-11-21

### Added
- **Exploit-DB research workflow** (`cveli exploits …`, TUI *Exploit-DB* view): local
  index of the official `files_exploits.csv` metadata with FTS5 search, fuzzy product
  matching, filters (CVE, EDB-ID, vendor, product, version, platform, type, author,
  dates, verified, has-CVE), sorting, pagination and saved searches. CVE detail views
  list matching exploit references. Exploit code is never downloaded.
- **Google Dork Builder** (`cveli dork …`, TUI view): 11 templates over 8 categories
  plus custom queries, per-operator explanations, copy buttons, safety policy that
  blocks credential/secret/dump/breach patterns, authorization confirmation and rate
  limits before opening a browser, privacy-preserving storage only on explicit save.
- **Metasploit research templates** (`cveli msf …`, TUI view, `M` on detail screens):
  `.rb` scaffold, Markdown research report and JSON metadata with the mandatory
  preflight checklist; no payload/exploitation code; export requires a research-only
  confirmation and is audited.
- **Opus 5.5 theme** and new TUI shell: navigation sidebar, command bar with global
  search, intel panel, command palette, dark (default) and light themes, responsive
  breakpoints, reduced motion, `NO_COLOR` support.
- Research **projects**, saved searches, local **audit log**, local-only **metrics**.
- Commands: `doctor`, `project`, `settings`, `jobs`, `cache`, `privacy`.
- Typed settings from environment/`.env`, versioned database migrations with
  automatic backups, shared HTTP client with retries and per-host rate limits.
- CI: ruff, mypy, pytest with coverage gate, `ruby -c` on generated templates,
  bandit, pip-audit.

### Fixed
See [docs/triage.md](docs/triage.md) for reproduction steps and regression tests.
- **B1 (data loss)** — saving a partial KEV/EPSS record overwrote stored CVSS,
  severity, dates and descriptions. Saves now merge field by field.
- B2 — `.env` / `NVD_API_KEY` / `CVELI_DB_PATH` / `CVELI_CACHE_DIR` were ignored.
- B3 — `import config.defaults` raised `ModuleNotFoundError`.
- B4 — the database and cache were written inside the installed package.
- B5 — `--range` did not filter locally cached results.
- B6 — NVD results were truncated to one page per window and not rate limited.
- B7 — the whole CISA KEV catalogue was downloaded and saved row-by-row on every
  search; EPSS was requested with 1,000+ IDs at once.
- B8 — feed text could inject Rich markup / terminal escape sequences.
- B9 — export path checks were bypassable; CSV formula injection.
- B10–B17 — input validation, TUI crash on invalid watchlist type, TUI launched
  without a terminal, KEV vs public-exploit flags, dead code, watchlist "new since
  last check", cache key gaps, timestamp consistency.

### Changed / upgrade notes
- **Data location**: the database moves to `~/.local/share/cveli/cveli.db` and the
  cache to `~/.cache/cveli`. A 0.1.x database at `storage/cveli.db` is copied there
  automatically on first run; the original file is left untouched.
- **Migrations**: the schema is upgraded automatically; a backup
  `cveli.db.bak-<timestamp>` is written next to the database first. To roll back,
  restore that file and reinstall 0.1.x.
- `search --exploits` is deprecated in favour of `--kev` (CISA KEV) and
  `--public-exploit` (Exploit-DB references).
- The root version flag is now `cveli -V` / `cveli --version` (was `-v`).
- KEV-only records no longer receive a default `Info` severity; unscored CVEs show
  `N/A`.
- `cveli search` without a terminal (pipes, scripts) prints a table instead of
  launching the TUI.

## 0.1.0
- Initial CVELI release.
