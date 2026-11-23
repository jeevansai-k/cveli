# CVELI

<div align="center">

```text
 ██████╗██╗   ██╗███████╗██╗     ██╗
██╔════╝██║   ██║██╔════╝██║     ██║
██║     ██║   ██║█████╗  ██║     ██║
██║     ╚██╗ ██╔╝██╔══╝  ██║     ██║
╚██████╗ ╚████╔╝ ███████╗███████╗██║
 ╚═════╝  ╚═══╝  ╚══════╝╚══════╝╚═╝
```

**CVELI 2.0 — search-first CVE & vulnerability intelligence for the terminal.**

*Created by **jeevansai-k***

![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Textual](https://img.shields.io/badge/TUI-Textual-00C7B7?style=for-the-badge)
![Typer](https://img.shields.io/badge/CLI-Typer%20%2B%20Rich-10B981?style=for-the-badge)
![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-F59E0B?style=for-the-badge)

</div>

CVELI unifies **NVD**, **CVE.org**, **CISA KEV**, **FIRST EPSS** and **Exploit-DB
metadata** in one fast, keyboard-first terminal app with an offline cache, a Google
Dork Builder with safety guardrails, and a generator for *non-weaponized*
Metasploit research templates — all styled with the new **Opus 5.5** theme.

> **Authorized, defensive use only.** CVELI never exploits, scans or contacts the
> systems you research. It does not download exploit code, scrape Google or
> Exploit-DB, or build credential/secret-hunting queries. You are responsible for
> having written authorization for anything you test.

---

## What's new in 2.0

| Area | Highlights |
|---|---|
| Reliability | 17 bugs fixed with regression tests — incl. a data-loss bug where KEV/EPSS refreshes wiped stored CVSS scores, `.env` settings being ignored, `--range` not filtering cached results, missing NVD pagination/rate limiting |
| Exploit-DB | Local index of the official `files_exploits.csv` (46k+ entries): search by CVE, EDB-ID, product (fuzzy), vendor, version, platform, type, author, date; cross-linked into every CVE |
| Dork Builder | Username + site → previewed, explained, copyable Google queries; blocks secret/credential/dump patterns; opening in a browser needs an authorization confirmation and is rate-limited |
| MSF templates | `.rb` scaffold + Markdown research report + JSON metadata for a CVE/EDB entry; no payload or exploit logic; export requires a research-only confirmation |
| Opus 5.5 design | New shell (navigation, command bar, intel panel, command palette), **Dark** (default) and **Light** themes, WCAG AA contrast tested, responsive down to 76 columns |
| Ops | XDG data paths, versioned DB migrations with automatic backup, `cveli doctor`, background jobs, local-only metrics, privacy purge |

See [CHANGELOG.md](CHANGELOG.md) for the full list and upgrade notes.

---

## Quick start

```bash
git clone https://github.com/jeevansai-k/cveli.git
cd cveli
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

```bash
cveli            # open the TUI shell
cveli --help     # all commands
cveli doctor     # check settings, paths and data sources
```

Optional: copy `.env.example` to `.env` and set `NVD_API_KEY` (raises the NVD
rate limit from 5 to 50 requests per 30 s).

---

## Command reference

### Search CVEs

```bash
cveli search openssl                     # last year, live + cache
cveli search CVE-2021-44228 --format detail
cveli search fortinet --range 5y --kev   # CISA KEV only
cveli search apache --public-exploit     # has Exploit-DB references
cveli search nginx --cache -f json       # offline, machine-readable
```

| Option | Description |
|---|---|
| `--severity` / `--min-cvss` / `--vendor` / `--cwe` | Filters (validated) |
| `--kev` · `--public-exploit` | CISA KEV listed · has Exploit-DB references (`--exploits` is a deprecated alias for `--kev`) |
| `--range` | `1m 3m 6m 9m 1y 2y 3y 4y 5y complete` — applies to live *and* cached results |
| `--live/--cache` | Query live sources first (default) or local data only |
| `--sort` | `published cvss epss updated id` |
| `--format` | `table` (TUI on a terminal, plain table otherwise), `json`, `markdown`, `detail`, `plain` |

### Exploit-DB research (metadata only)

```bash
cveli exploits refresh                      # downloads files_exploits.csv if changed (24 h TTL)
cveli exploits refresh --from-path /usr/share/exploitdb   # offline / SearchSploit install
cveli exploits search --cve CVE-2021-44228
cveli exploits search --product "wordpress" --version 5.8 --type webapps --verified
cveli exploits search apache --platform linux --since 2023-01-01 --save linux-apache
cveli exploits search --load linux-apache -f json
cveli exploits show EDB-50592
cveli exploits status
```

Every result shows provenance (Exploit-DB link, original advisory), date, platform,
type, author, verified status and **safety labels** (`Research only`,
`Requires authorized environment`, `Proof-of-concept reference`, `Unverified`, …).

### Google Dork Builder

```bash
cveli dork sites
cveli dork build --username alice --site github.com
cveli dork build -u @alice -s snapchat                      # platform names and @handles work
cveli dork build -u alice --category social                 # 22 social networks, no site needed
cveli dork build -u alice -s example.com --category documents --filetype pdf
cveli dork build -s example.com --category subdomains        # medium risk, warned
cveli dork open  -t public_profile_domain -u alice -s example.com   # asks for confirmation
cveli dork save  --project "Case 42" -u alice -s example.com
```

For social networks (Snapchat, Instagram, TikTok, X/Twitter, Facebook, Threads,
Reddit, YouTube, LinkedIn, Telegram, Bluesky, …) CVELI matches each platform's
public profile URL (e.g. `snapchat.com/add/<user>`, `tiktok.com/@<user>`), because
the username often isn't in the indexed page text.

Categories: profiles, social media accounts, posts, documents, files, code, subdomains, login pages, public
directories, custom. Every operator is explained. Queries for passwords, tokens,
keys, config files, database dumps or breach data are **blocked**, including in
custom queries. CVELI never runs searches itself.

### Metasploit research templates

```bash
cveli msf generate --cve CVE-2021-44228                 # preview .rb
cveli msf generate --edb 50592 --preview md             # preview the report
cveli msf generate --cve CVE-2021-44228 --out reports/  # export (asks for confirmation)
cveli msf history
```

The scaffold has the full metadata block, `check` returning `CheckCode::Unknown`,
an action method that always stops with `fail_with`, TODO markers and the
mandatory preflight checklist (authorization, scope, version confirmation,
backup/rollback, non-production validation, disclosure plan).

### Other commands

```bash
cveli sync --source all            # nvd, cve_org, cisa_kev, epss
cveli export openssl -o report.csv -f csv
cveli watchlist add -t vendor -v Fortinet && cveli watchlist check
cveli project create "Case 42" && cveli project add "Case 42" cve CVE-2024-3400
cveli settings theme light         # dark | light | auto
cveli jobs run due                 # cron-friendly refresh of stale data
cveli privacy notice
cveli privacy purge
cveli stats
cveli cache status
```

---

## The TUI shell

```text
┌ CVELI ─ [ Search CVE-ID, EDB-ID or keyword ( / ) ] ─────────── EDB 11-21 · KEV 11-21 ┐
│ 1 ⌂ Dashboard     │ Search CVEs                                 │ Intel               │
│ 2 ⌕ Search CVEs   │ [openssl            ] [1 year ▾] ☑ Live     │ CVE-2024-3400       │
│ 3 ⚑ Exploit-DB    │ CVE ID          Severity    CVSS  EPSS  KEV │ Severity ◆ CRITICAL │
│ 4 ⚲ Dork Builder  │ CVE-2024-3400   ◆ CRITICAL  10.0  94.3% YES │ EPSS     94.3%      │
│ 5 ⎔ MSF Templates │ …                                           │ Exploit-DB 3 refs   │
│ 6 ◉ Watchlist     │                                             │                     │
│ 7 ▤ Projects      │                                             │                     │
│ 8 ⚙ Settings      │                                             │                     │
└ ^q Quit  ^t Theme  ^b Nav  f2 Intel ──────────────────────────────────── ^p palette ┘
```

| Key | Action |
|---|---|
| `1`–`8` | Switch view |
| `/` or `Ctrl+F` | Global search (CVE-ID, `EDB-…` or keyword) |
| `Ctrl+P` | Command palette (navigate, theme, refresh data, jump to CVE/EDB, **Keys** guide — select it again to close) |
| `Ctrl+T` | Toggle Dark / Light theme |
| `P` | Add the selected CVE / exploit / dork to an existing or new project |
| `Delete` | Remove the selected watchlist entry (or use **Remove selected**) |
| `Ctrl+B` / `F2` | Toggle navigation / intel panel |
| `Enter` / `Esc` | Open / back · `M` research template from a detail screen |
| `Alt+←/→` | Previous / next page in `cveli search` results |
| `Ctrl+Q` | Quit |

Accessibility: every colour pair meets WCAG 2.2 AA contrast (tested), focus is
always visible, severity is shown as symbol + word (never colour alone), motion can
be reduced (`cveli settings motion --reduce` or `CVELI_REDUCE_MOTION=1`), and every
feature has a plain CLI equivalent with `--format json` for screen readers and
scripts. `NO_COLOR` is honoured. A monospace font with good Unicode coverage
(JetBrains Mono, Fira Code, Cascadia Code) renders the icons best.

---

## Data sources

| Source | Used for | Access |
|---|---|---|
| NVD API 2.0 | CVSS, CWE, products, references, dates | rate-limited, paginated, optional API key |
| CVE.org | Official CVE records | exact CVE IDs |
| CISA KEV | Known exploited status + date | catalogue cached 24 h |
| FIRST EPSS | Exploit prediction score + percentile | batched ≤100 IDs |
| Exploit-DB | Public exploit **metadata** (`files_exploits.csv`, GPL-2.0) | conditional GET, 24 h TTL, or local checkout |

Missing values are shown as **N/A** — CVELI never fabricates scores, vendors, dates
or descriptions.

---

## Configuration

All settings come from the environment or a `.env` file (current directory or
`~/.config/cveli/.env`); see [.env.example](.env.example). Key variables:

| Variable | Default |
|---|---|
| `NVD_API_KEY` | unset |
| `CVELI_DATA_DIR` / `CVELI_DB_PATH` | `~/.local/share/cveli/cveli.db` |
| `CVELI_CACHE_DIR` | `~/.cache/cveli` |
| `EXPLOITDB_PATH` | unset (auto-detects `/usr/share/exploitdb`) |
| `CVELI_FEATURE_EXPLOITDB` / `_DORKS` / `_MSF` | `1` |
| `CVELI_THEME` | saved preference, else `auto` |

---

## Privacy

Usernames, domains and dorks stay in memory and are redacted from logs. They are
stored only when you explicitly save them to a project. The audit log records
event types and identifiers only (90-day retention); local metrics never leave
your machine. `cveli privacy purge` deletes all saved research data.

---

## Development

```bash
make test        # pytest
make lint        # ruff
make typecheck   # mypy on the 2.0 modules
make cov         # coverage report
pytest -m live   # opt-in smoke tests against real services
```

Docs: [architecture](docs/architecture.md) · [API & JSON contracts](docs/api.md) ·
[operations](docs/operations.md) · [bug triage](docs/triage.md) ·
[contributing](docs/contributing.md)

---

## License

MIT — see [LICENSE](LICENSE). Exploit-DB metadata is © OffSec, GPL-2.0, and is
subject to the [Exploit-DB terms](https://www.exploit-db.com/terms).
