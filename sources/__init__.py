"""
Data Source Adapters.

Purpose: Implement adapters for fetching CVE data from various sources.
Inputs: Query parameters, API keys, source identifiers.
Outputs: Normalized CVE records from external sources.
Responsibilities: Fetch, parse, and normalize data from NVD, CVE.org, vendors.
Dependencies: httpx, pydantic, core.models.CVEModel.
"""

from .base import BaseAdapter
from .cve_org import CVEOrgAdapter
from .epss import EPSSAdapter
from .nvd import NVDAdapter
from .vendor import CISAKEVAdapter

__all__ = [
    "BaseAdapter",
    "NVDAdapter",
    "CVEOrgAdapter",
    "EPSSAdapter",
    "CISAKEVAdapter",
]
