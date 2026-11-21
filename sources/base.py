"""
Base Source Adapter Interface.

Purpose: Define the contract for all data source adapters (NVD, CVE.org, vendors).
Inputs: Request parameters for fetching/parsing/normalizing data.
Outputs: Normalized CVE records as dictionaries.
Responsibilities: Provide consistent interface across different sources.
Dependencies: httpx for HTTP requests, lxml/beautifulsoup4 for HTML parsing.

Functions/Classes:
    - BaseAdapter: Abstract base class with required methods
    - fetch(): Fetch raw data from source URL/API endpoint
    - parse(): Parse and extract CVE records from fetched data
    - normalize(): Convert to canonical CVE format

Example:
    From nvd.py:
        # Implement the interface
        class NVDAdapter(BaseAdapter):
            def fetch(self, ...):  # Must implement this
                pass

"""

from abc import ABC, abstractmethod
from typing import Any

from utils.http import HttpClient


class BaseAdapter(ABC):
    """Abstract base class for all data source adapters.

    Purpose: Define the contract that all CVE source adapters must implement.

    Responsibilities:
        - Fetch raw data from external sources (NVD, CVE.org, vendor advisories)
        - Parse HTML/XML responses into structured records
        - Normalize extracted data to canonical CVE format

    Required Methods:
        - fetch(): Return raw data for given query parameters
        - parse(): Extract CVE records from raw data
        - normalize(): Convert to standard schema

    Example:
        From nvd.py:
            class NVDAdapter(BaseAdapter):
                def __init__(self, api_key):
                    self.api_key = api_key

                @abstractmethod
                def fetch(self, ...):  # Must implement this
                    pass
    """

    name = "base_adapter"

    endpoint = "source"

    def __init__(self, api_key: str | None = None, timeout: float | None = None):
        self.api_key = api_key or ""
        self.http = HttpClient(self.endpoint, timeout=timeout)
        self.timeout = self.http.timeout

    @abstractmethod
    def fetch(self, query_params: dict[str, Any] | None = None) -> str | bytes:
        """Fetch raw data from the source.

        Purpose: Retrieve raw HTML/XML/JSON data from the external source.

        Inputs:
            - query_params: URL parameters for fetching (CVE IDs, filters, etc.)

        Outputs:
            - Raw response as string or binary

        Responsibilities:
            - Make HTTP request with proper headers and authentication
            - Handle redirects automatically via httpx
            - Return raw unprocessed data

        Example:
            # Fetch NVD feed for a specific CVE
            adapter.fetch(query_params={"cve_id": "CVE-2024-12345"})

        Example:
            # Fetch full NVD API feed
            adapter.fetch(query_params={})  # Returns entire feed
        """
        raise NotImplementedError("Must implement fetch() method")

    @abstractmethod
    def parse(self, raw_data: str | bytes) -> list[dict[str, Any]]:
        """Parse raw data into CVE records.

        Purpose: Extract CVE information from fetched response data.

        Inputs:
            - raw_data: Raw HTML/XML/JSON content from fetch()

        Outputs:
            - List of parsed CVE record dictionaries

        Responsibilities:
            - Parse appropriate format (HTML, XML, JSON) based on source type
            - Extract relevant fields for each CVE
            - Handle malformed or partial data gracefully

        Example:
            # Parse NVD XML feed into list of CVE dicts
            records = adapter.parse(nvd_xml_response)

        Each record should have the canonical schema structure.
        """
        raise NotImplementedError("Must implement parse() method")

    @abstractmethod
    def normalize(self, record: dict[str, Any]) -> dict[str, Any]:
        """Normalize a single record to standard format.

        Purpose: Ensure consistent field names and data types across all sources.

        Inputs:
            - record: Raw parsed record from source-specific parse() method

        Outputs:
            - Normalized CVE record with canonical schema

        Responsibilities:
            - Map source-specific fields to standard keys
            - Normalize string formats (dates, versions, etc.)
            - Handle missing/null values consistently

        Example:
            # Convert vendor's custom format to standard
            normalized = adapter.normalize(raw_record)

        The output matches the canonical CVE schema.
        """
        raise NotImplementedError("Must implement normalize() method")
