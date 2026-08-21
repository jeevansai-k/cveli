import os

DEFAULT_SETTINGS = {
    "app_name": "cveli",
    "version": "0.1.0",
    "nvd_api_key": "",
    "cve_org_api_key": "",
}


def get_setting(key: str, default_value=None):
    return os.environ.get(key.upper(), DEFAULT_SETTINGS.get(key.lower(), default_value))
