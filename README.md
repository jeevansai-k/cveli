<div align="center">

# 🛡️ `cveli` — Search-First CVE & Vulnerability CLI/TUI

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg?style=flat-square)](https://github.com/astral-sh/ruff)
[![Type Checked: mypy](https://img.shields.io/badge/type%20checked-mypy-blueviolet.svg?style=flat-square)](https://mypy-lang.org/)
[![Tests Passing](https://img.shields.io/badge/tests-80%20passed-success.svg?style=flat-square)]()
[![Built with Textual & Typer](https://img.shields.io/badge/UI-Typer%20%2B%20Rich%20%2B%20Textual-orange.svg?style=flat-square)](https://textual.textualize.io/)

**A blazing-fast, offline-first command-line interface and interactive terminal dashboard (TUI) for searching, monitoring, and triaging Common Vulnerabilities and Exposures (CVEs).**

[Features](#-key-features) • [Why cveli?](#-why-cveli) • [Quickstart](#-quickstart) • [Usage & Commands](#-command-reference) • [Interactive TUI](#-interactive-tui-mode) • [Architecture](#-architecture)

</div>

---

## 💡 Why `cveli`?

Security engineers, DevOps teams, and developers often need to check vulnerability impact instantly without leaving their terminal or clicking through slow web consoles.

- ⚡ **Zero-Friction Terminal Velocity:** Query CVEs by keywords, severity, CVSS scores, EPSS probabilities, CWE identifiers, or affected vendors with sub-second response times.
- 💾 **Local-First SQLite & Disk Caching:** Synchronizes vulnerability feeds (NVD, CISA KEV) to local storage so you can search completely offline or behind restricted air-gapped environments.
- 🖥️ **Rich TUI + Unix Scriptable CLI:** Enjoy an interactive Textual terminal dashboard with keyboard navigation, or pipe structured JSON/CSV/Markdown output straight into your CI/CD pipelines and vulnerability assessment workflows.
- 🎯 **Proactive Watchlist Alerts:** Monitor software dependencies, mission-critical infrastructure vendors (e.g., `OpenSSL`, `nginx`, `Fortinet`), or specific CWE types.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| **🔍 Search & Filter Engine** | Search by keyword, vendor, CVSS score (`--min-cvss`), EPSS exploit probability, CWE ID, or active CISA KEV exploitation flags. |
| **🔄 Multi-Source Sync** | Ingest up-to-date vulnerability feeds directly from **NIST NVD** (API 2.0) and **CISA Known Exploited Vulnerabilities (KEV)** catalog. |
| **📊 Interactive TUI Dashboard** | Fullscreen terminal UI built with Textual: real-time live search, interactive CVE inspector, CVSS gauge, and filter drawer. |
| **👀 Watchlist Engine** | Save monitored vendors, products, or CWE categories and trigger instant status checks against new advisories. |
| **📤 Multi-Format Export** | Export search results and cached vulnerability subsets directly to **JSON**, **CSV**, **Markdown**, or plain text. |
| **📈 Local Database & Stats** | SQLite storage with automatic index optimization and disk cache layer for instant fuzzy search and breakdown analytics. |

---

## 🚀 Quickstart

### Prerequisites
- Python **3.12+**
- `git`

### Installation

Clone the repository and set up a clean virtual environment:

```bash
# Clone the repository
git clone https://github.com/jeevansai-k/cve-cli.git
cd cve-cli

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with development tools
pip install --upgrade pip
pip install -e ".[dev]"
```

Verify the installation:

```bash
cveli --help
```

---

## 📖 Command Reference

### 1. Ingest & Sync Feeds (`cveli sync`)
Fetch and cache vulnerability records from external feeds into the local SQLite database.

```bash
# Sync recent vulnerabilities matching a query (e.g. OpenSSL)
cveli sync --query openssl --limit 50

# Sync recent high-priority vulnerabilities from all sources (NVD + CISA KEV)
cveli sync --limit 100
```

---

### 2. Search & Triage (`cveli search`)
Search through local records with rich color-coded terminal tables and interactive selection.

```bash
# Basic keyword search
cveli search openssl

# Filter by minimum CVSS score and severity
cveli search linux --min-cvss 8.5 --severity Critical

# Filter for vulnerabilities with confirmed in-the-wild exploits (CISA KEV)
cveli search microsoft --exploit-only

# Filter by specific CWE category and vendor
cveli search --vendor apache --cwe CWE-79

# Filter by publication timeframe (1m, 3m, 6m, 1y, 2y, 5y, complete)
cveli search kubernetes --range 6m --limit 25
```

#### Output Formats & Interactive Selection
```bash
# Open an interactive detail browser directly in the terminal
cveli search fortinet --interactive

# Print as clean JSON to pipe into jq or tools
cveli search nginx --format json | jq '.[] | {id: .id, cvss: .cvss}'

# Output as formatted Markdown table
cveli search sudo --format md
```

---

### 3. Interactive TUI Mode (`cveli tui`)
Launch the terminal user interface for mouse and keyboard-driven vulnerability inspection:

```bash
cveli tui
```
*(Or simply execute `cveli` with no arguments to launch the TUI directly).*

**Keybindings:**
- `q` / `Ctrl+C` — Quit TUI
- `Tab` / `Shift+Tab` — Focus search input / result table
- `Up` / `Down` — Navigate through CVE items
- `Enter` — Open detailed vulnerability inspector

---

### 4. Watchlist Monitoring (`cveli watchlist`)
Track critical components in your software stack and inspect their exposure.

```bash
# Add targets to watchlist
cveli watchlist add --type vendor --value "OpenSSL" --notes "Core crypto library"
cveli watchlist add --type product --value "PostgreSQL"
cveli watchlist add --type cwe --value "CWE-89" --notes "SQL Injection"

# List all tracked targets
cveli watchlist list

# Check matching vulnerability alerts for your watchlist
cveli watchlist check

# Remove a target by ID
cveli watchlist remove --id <TARGET_ID>
```

---

### 5. Export Reports (`cveli export`)
Export filtered security records to share with compliance, engineering, or audit teams:

```bash
# Export to JSON
cveli export openssl --output reports/openssl.json --format json

# Export high/critical CVEs to CSV
cveli export --severity High --output reports/high_vulns.csv --format csv

# Export summary report to Markdown
cveli export linux --severity Critical --output reports/linux_critical.md --format markdown
```

---

### 6. Vulnerability Statistics (`cveli stats`)
Inspect local cache telemetry, severity distribution, and total indexed records:

```bash
cveli stats
```

---

## ⚙️ Configuration

Optional configuration can be defined via environment variables or a `.env` file in the project root:

```ini
# Optional: NIST NVD API key to avoid strict public rate limiting
NVD_API_KEY=your_nvd_api_key_here

# Optional: Custom database and cache paths
CVELI_DB_PATH=storage/cveli.db
CVELI_CACHE_DIR=.cache/cveli
CVELI_LOG_LEVEL=INFO
```

---

## 🏗️ Architecture

```
cve-cli/
├── cli/                # User Interface Layer
│   ├── app.py          # Typer application entry point & routing
│   ├── commands/       # CLI subcommands (search, sync, export, watchlist, stats)
│   └── tui/            # Textual TUI dashboard & interactive widgets
├── core/               # Domain Business Logic
│   ├── models.py       # Pydantic v2 data models (CVEModel, CWEID, etc.)
│   ├── search.py       # Query processing & token matching
│   ├── filters.py      # Severity, CVSS, EPSS & timeframe filters
│   └── formatter.py    # Rich terminal tables, panels & exporters
├── sources/            # Upstream Feed Adapters
│   ├── nvd.py          # NIST NVD API 2.0 client
│   ├── cve_org.py      # CVE.org vulnerability feed parser
│   └── vendor.py       # CISA KEV & vendor feed adapters
├── services/           # Service Orchestration Layer
│   ├── sync.py         # Multi-feed ingestion & normalization
│   ├── export.py       # JSON/CSV/Markdown/Text serialization
│   └── watchlist.py    # Target CRUD & vulnerability matching
├── storage/            # Data & Persistence Layer
│   ├── database.py     # SQLite schema & SQLAlchemy 2.0 ORM session
│   ├── repositories.py # CVERepository data access layer
│   └── cache.py        # DiskCache query acceleration layer
└── tests/              # Test suite (80 unit & integration tests)
```

---

## 🧪 Testing & Quality

`cveli` is thoroughly tested across all core layers with `pytest`, `mypy`, and `ruff`:

```bash
# Run test suite
pytest -v

# Run with coverage report
pytest --cov=. --cov-report=term-missing

# Lint & formatting check
ruff check .
ruff format --check .

# Static type checking
mypy cli core services sources storage
```

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m "feat: add amazing feature"`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for details.
