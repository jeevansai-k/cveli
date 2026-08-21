DEFAULT_APP_SETTINGS = {
    "name": "cveli",
    "version": "0.1.0",
    "log_level": "INFO",
}

DEFAULT_API_SETTINGS = {
    "nvd_api_key": "",
    "cve_org_api_key": "",
    "user_agent": "cveli/0.1.0",
    "timeout_seconds": 30,
}

DEFAULT_RATE_LIMITS = {
    "nvd_per_minute": 60,
    "cve_org_per_minute": 30,
    "vendor_per_minute": 20,
}

DEFAULT_SYNC_SETTINGS = {
    "enabled": True,
    "interval_minutes": 1440,
    "sources_to_sync": ["nvd", "cisa_kev"],
}

DEFAULT_DB_SETTINGS = {
    "path": "storage/cveli.db",
    "max_cache_size_mb": 100,
}

DEFAULT_CACHE_SETTINGS = {
    "default_max_entries": 5000,
    "default_max_age_seconds": 604800,
    "default_ttl_per_source": {
        "nvd": 1209600,
        "cve_org": 86400,
        "vendor": 3600,
    },
}
