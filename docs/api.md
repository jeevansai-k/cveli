# CVELI 2.0 service contracts and JSON output

CVELI is local software, so its "API" is a set of typed Python services. Every
service is mirrored by a CLI command whose `--format json` / `--json` output is a
stable contract for scripts. Errors are typed (`utils/errors.py`) and map to exit
codes.

| Exit code | Meaning |
|---|---|
| 0 | success |
| 1 | nothing found / operation failed (e.g. refresh error) |
| 2 | invalid input or blocked by policy (`ValidationError`, `PolicyError`) |
| 3 | feature disabled by a `CVELI_FEATURE_*` flag |
| 4 | authorization/confirmation not given or rate limited |

## CVE search — `services.sync.SyncService`, `storage.repositories.CVERepository`

```python
CVERepository().search(query="openssl", severity="High", kev_only=True,
                       public_exploit_only=False, published_since="2025-01-01",
                       sort_by="cvss", limit=100) -> list[CVEModel]
SyncService().sync_sources(sources=["nvd", "cisa_kev", "epss"], query="openssl",
                           limit=500, date_range=(start, end), force=False)
    -> {"total_synced": int, "unique_records": int, "sources": {...}, "errors": {...}}
```

`cveli search openssl --cache -f json` prints a list of `CVEModel` objects:

```json
[{"id": "CVE-2024-1234", "summary": "…", "severity": "High", "cvss": 8.1,
  "vector": "CVSS:3.1/…", "published": "2024-01-02", "updated": "2024-02-03",
  "kev": true, "kev_date": "2024-03-01", "public_exploit_count": 2,
  "exploit_available": true, "epss": 0.42, "epss_percentile": 0.97,
  "vendor": "openssl", "cwe": {"id": 787, "name": "CWE-787"},
  "affected_products": [{"name": "openssl/openssl", "version": "3.0.0"}],
  "references": ["https://…"], "reference_details": [{"url": "https://…",
  "source": "…", "tags": ["Patch"]}], "tags": ["cisa_kev"],
  "sources": ["NVD", "CISA KEV", "FIRST EPSS"], "fetched_at": "2026-11-21"}]
```

## Exploit-DB — `services.exploitdb.ExploitDBService`

```python
service.refresh(force=False, from_path=None) -> RefreshResult
    # status: updated | not_modified | fresh | error; rows; origin; duration_ms; message
service.search(ExploitQuery(text="", cve_id=None, edb_id=None, vendor=None,
               product=None, version=None, platform=None, type=None, author=None,
               since=None, until=None, verified=None, has_cve=None, sort="date",
               descending=True, page=1, page_size=25)) -> Page[ExploitModel]
service.get(edb_id) -> ExploitModel | None
service.for_cve(cve_id) -> list[ExploitModel]
service.status() -> dict
```

`cveli exploits search --cve CVE-2021-44228 -f json`:

```json
{"query": {"cve_id": "CVE-2021-44228", "page": 1, "page_size": 25},
 "total": 3, "page": 1, "pages": 1,
 "source_status": {"exploitdb": {"last_success": "2026-11-21T13:38:07Z",
                                 "stale": false, "rows": 46710}},
 "results": [{"edb_id": 50592, "cve_ids": ["CVE-2021-44228"], "aliases": [],
   "title": "Apache Log4j 2 - Remote Code Execution (RCE)", "description": null,
   "author": "…", "date_published": "2021-12-14", "platform": "java",
   "type": "remote", "port": null, "verified": false,
   "source_url": "https://www.exploit-db.com/exploits/50592",
   "advisory_url": "", "file_url": "https://gitlab.com/…/50592.py",
   "tags": [], "license": "GPL-2.0 (Exploit-DB repository metadata)",
   "affected_product": "Apache Log4j 2", "affected_versions": [],
   "parsed_heuristically": true,
   "safety_labels": ["Research only", "Requires authorized environment",
                     "Proof-of-concept reference", "Unverified"]}],
 "notice": "Public exploit references do not imply safe, legal, or authorized use. …",
 "attribution": "Exploit metadata from Exploit-DB (OffSec) …"}
```

## Dork Builder — `services.dorks.DorkBuilder`

```python
DorkBuilder().build(DorkInput(username="alice", target_domain="example.com",
    category="profiles", exact_match=True, exclude_false_positives=False,
    filetype=None, include_phrases=[], exclude_phrases=[], custom_query=""))
    -> list[DorkQuery]              # raises ValidationError / PolicyError
DorkBuilder().open(dork, attested=True) -> str  # AuthorizationRequiredError, RateLimitError
```

`cveli dork build -u alice -s example.com -f json` (first element):

```json
{"id": "public_profile_domain", "label": "Public profile mentions",
 "category": "profiles", "target_domain": "example.com", "username": "alice",
 "query": "site:example.com \"alice\"",
 "operators": [
   {"op": "site:", "value": "example.com",
    "explanation": "Restricts results to example.com and its subdomains."},
   {"op": "\"\"", "value": "\"alice\"", "explanation": "Exact phrase match for \"alice\"."}],
 "explanation": "Finds pages on example.com that mention the username.",
 "risk_level": "low", "requires_authorization": true,
 "warnings": ["Only research people and organisations you are authorized to …"],
 "google_url": "https://www.google.com/search?q=site%3Aexample.com+%22alice%22"}
```

## Research templates — `services.msf_template.MsfTemplateService`

```python
service.generate(cve_id=None, edb_id=None, module_type="auto",
                 author="CVELI Research", live=True) -> TemplateBundle
service.export(bundle, out_dir, formats=("rb", "md", "json"), confirmed=False,
               allow_outside=False, project=None) -> list[str]
```

`cveli msf generate --cve CVE-2021-44228 --out reports --confirm-research -f json`:

```json
{"module_type": "exploit", "module_class": "Msf::Exploit::Remote",
 "files": ["reports/cveli_research_cve_2021_44228.rb",
           "reports/cveli_research_cve_2021_44228.md",
           "reports/cveli_research_cve_2021_44228.json"],
 "preflight": ["Written authorization from the system owner …", "…"]}
```

The `.json` file follows schema `cveli.msf-template/1` (`record_id`, `module_type`,
`module_class`, `cve_id`, `edb_ids`, `affected_product`, `affected_versions`,
`disclosure_date`, `references`, `preflight_checklist`, `safety`).

## Projects, settings, jobs, diagnostics

| Service | CLI |
|---|---|
| `ProjectService.create/list/show/add/save_dork/delete/purge_all` | `cveli project …`, `cveli dork save`, `cveli privacy purge` |
| `SettingsRepository.get/set` | `cveli settings theme|motion|show` |
| `services.jobs.run_job(name, force)` / `run_due_jobs()` | `cveli jobs run <name|due>` |
| `AuditService.record/recent` | (local only) |
| `cli.commands.doctor_cmd.collect()` | `cveli doctor --json` |

## Core library helpers

`core.search.parse_query / fuzzy_match / execute_search`, `core.filters.apply_filters`,
`core.ranking.rank_results` and `core.validator.validate_*` remain available as a
small library API; `fuzzy_match` powers Exploit-DB product matching and the
validators guard CLI input.
