# Operating CVELI 2.0

## Data locations

| What | Default | Override |
|---|---|---|
| Database | `~/.local/share/cveli/cveli.db` | `CVELI_DATA_DIR`, `CVELI_DB_PATH` |
| Query cache | `~/.cache/cveli/diskcache` (256 MB cap) | `CVELI_CACHE_DIR`, `CVELI_CACHE_SIZE_MB` |
| Logs | `~/.cache/cveli/logs/cveli.log` (1 MB × 3) | `CVELI_LOG_DIR` |
| Config `.env` | `./.env`, `~/.config/cveli/.env` | `CVELI_CONFIG_DIR`, `CVELI_DISABLE_DOTENV=1` |

Run `cveli doctor` to see the effective values (secrets masked), schema version,
FTS5 availability, data-source freshness and local metrics.

## Background jobs

CVELI has no daemon. Jobs run lazily when data is stale, in worker threads from the
TUI (Settings view, command palette), or explicitly:

| Job | What it does | Default cadence |
|---|---|---|
| `exploitdb_refresh` | Conditional download of `files_exploits.csv`, rebuild index | 24 h |
| `cve_enrichment` | Refresh CISA KEV catalogue + EPSS for stored CVEs (≤100 per request) | 24 h |
| `cache_cleanup` | Expire/cull cache, purge old metrics and audit entries | each run |
| `index_rebuild` | Rebuild FTS5 index and `public_exploit_count` | on demand |

```bash
cveli jobs run due              # only what is stale
cveli jobs run exploitdb_refresh --force
```

Cron example (daily at 03:17):

```cron
17 3 * * * /path/to/cveli/.venv/bin/cveli jobs run due >> ~/.cache/cveli/jobs.log 2>&1
```

systemd user timer: create `~/.config/systemd/user/cveli-jobs.service` with
`ExecStart=/path/to/.venv/bin/cveli jobs run due` and a matching `.timer` with
`OnCalendar=daily`, then `systemctl --user enable --now cveli-jobs.timer`.

## Offline Exploit-DB

```bash
git clone https://gitlab.com/exploit-database/exploitdb.git ~/exploitdb   # or apt install exploitdb
cveli exploits refresh --from-path ~/exploitdb
export EXPLOITDB_PATH=~/exploitdb    # use it automatically
```

If the network download fails, CVELI falls back to a detected local dataset and
otherwise keeps serving the last good index (marked stale).

## Upgrading from 0.1.x

On first run CVELI copies `storage/cveli.db` from the source checkout to the new
data directory, writes `cveli.db.bak-<timestamp>`, and applies migrations 1–4.
Rollback: restore the backup file and reinstall the previous version.

## Privacy and retention

* Usernames, target domains and dork queries are never logged or written to
  metrics; they are stored only in `dork_saved` when you save them to a project.
* `audit_log` keeps event types and identifiers for `CVELI_AUDIT_RETENTION_DAYS`
  (default 90); `metrics` for `CVELI_METRICS_RETENTION_DAYS` (default 30);
  `cveli jobs run cache_cleanup` enforces both.
* `cveli privacy purge` removes projects, saved dorks/searches, report records and
  the audit log. Disable metrics with `CVELI_METRICS=0`.

## Feature flags

`CVELI_FEATURE_EXPLOITDB`, `CVELI_FEATURE_DORKS`, `CVELI_FEATURE_MSF` (default `1`).
A disabled feature hides its TUI view and makes its commands exit with code 3.

## Troubleshooting

| Symptom | Check |
|---|---|
| NVD 403/429 | set `NVD_API_KEY`; CVELI already retries with backoff |
| Exploit-DB empty | `cveli exploits status`; refresh or set `EXPLOITDB_PATH` |
| Odd colours | `cveli settings theme dark|light`; `NO_COLOR=1` for plain output |
| TUI won't start in scripts | expected — without a TTY commands print tables/JSON |
| Logs | `~/.cache/cveli/logs/cveli.log` (inputs redacted) |
