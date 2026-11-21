"""Static default values shared by settings and documentation."""

from config.version import APP_NAME, USER_AGENT, __version__

EXPLOITDB_CSV_URL = (
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
)

DEFAULT_SETTINGS = {
    "app_name": APP_NAME,
    "version": __version__,
    "nvd_api_key": "",
    "cve_org_api_key": "",
    "exploitdb_url": EXPLOITDB_CSV_URL,
}

DEFAULT_APP_SETTINGS = {
    "name": APP_NAME,
    "version": __version__,
    "log_level": "INFO",
}

DEFAULT_API_SETTINGS = {
    "nvd_api_key": "",
    "cve_org_api_key": "",
    "user_agent": USER_AGENT,
    "timeout_seconds": 30,
}

DEFAULT_SYNC_SETTINGS = {
    "enabled": True,
    "sources_to_sync": ["nvd", "cisa_kev"],
}

DEFAULT_CACHE_SETTINGS = {
    "size_limit_mb": 256,
    "search_ttl_seconds": 3600,
    "kev_ttl_hours": 24,
    "exploitdb_ttl_hours": 24,
}
