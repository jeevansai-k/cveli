# cveli

Small CVE CLI/TUI backed by SQLite.

## What it does

- Sync CVEs from NVD and CISA KEV
- Search cached CVEs by keyword, vendor, severity, and CWE
- Export results as JSON, CSV, Markdown, or text
- Track simple watchlist targets
- Show a minimal Textual TUI

## Quick start

```bash
cd /home/baymax/cve-cli
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cveli --help
```

## Common commands

```bash
cveli version
cveli sync --query openssl --limit 20
cveli search openssl
cveli stats
cveli watchlist add --type vendor --value OpenSSL
cveli tui
```

## Tests

```bash
.venv/bin/pytest -q
```

## Run guide

See `run-cveli.txt`.
