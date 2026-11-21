"""
Canonical data models.

Purpose: Pydantic models shared by sources, storage, services and UI.
Rule: missing upstream values stay ``None``/empty and render as N/A — CVELI never
fabricates CVSS, EPSS, vendors, dates, products or descriptions.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator

DATE_PATTERN = r"^$|^\d{4}-\d{2}-\d{2}$"


class CWEID(BaseModel):
    id: int
    name: str


class Reference(BaseModel):
    url: str
    source: str = ""
    tags: list[str] = Field(default_factory=list)


class CVEModel(BaseModel):
    id: str
    summary: str
    severity: str | None = Field(
        default=None, pattern=r"^(Critical|High|Medium|Low|Info)$"
    )
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    vector: str | None = None
    published: str = Field(default="", pattern=DATE_PATTERN)
    updated: str = Field(default="", pattern=DATE_PATTERN)
    kev_date: str = Field(default="", pattern=DATE_PATTERN)
    affected_products: list[dict] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    reference_details: list[Reference] = Field(default_factory=list)
    # Deprecated umbrella flag: True when listed in CISA KEV *or* when public
    # exploit references exist. Prefer ``kev`` / ``public_exploit_count``.
    exploit_available: bool = False
    kev: bool = False
    public_exploit_count: int = Field(default=0, ge=0)
    epss: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    vendor: str | None = None
    cwe: CWEID | None = None
    tags: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    fetched_at: str = ""

    @model_validator(mode="after")
    def _derive_flags(self) -> CVEModel:
        if "cisa_kev" in self.tags:
            self.kev = True
        if self.kev or self.public_exploit_count > 0:
            self.exploit_available = True
        return self

    @classmethod
    def from_dict(cls, data: dict) -> CVEModel:
        return cls(**data)

    def to_dict(self) -> dict:
        return self.model_dump()


class SafetyLabel(StrEnum):
    INFORMATIONAL = "Informational"
    POC_REFERENCE = "Proof-of-concept reference"
    PATCH_REFERENCE = "Patch reference"
    UNVERIFIED = "Unverified"
    REQUIRES_AUTHORIZED_ENV = "Requires authorized environment"
    RESEARCH_ONLY = "Research only"


class ExploitModel(BaseModel):
    """Exploit-DB *metadata* (never exploit code)."""

    edb_id: int = Field(ge=1)
    cve_ids: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    title: str
    description: str | None = None
    author: str = ""
    date_published: str = Field(default="", pattern=DATE_PATTERN)
    date_added: str = Field(default="", pattern=DATE_PATTERN)
    date_updated: str = Field(default="", pattern=DATE_PATTERN)
    platform: str = ""
    type: str = ""
    port: int | None = None
    verified: bool = False
    file_path: str = ""
    file_url: str = ""
    source_url: str = ""
    advisory_url: str = ""
    tags: list[str] = Field(default_factory=list)
    license: str = ""
    affected_product: str | None = None
    affected_versions: list[str] = Field(default_factory=list)
    parsed_heuristically: bool = True
    safety_labels: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class ExploitQuery(BaseModel):
    text: str = ""
    cve_id: str | None = None
    edb_id: int | None = None
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    platform: str | None = None
    type: str | None = None
    author: str | None = None
    since: str | None = Field(default=None, pattern=DATE_PATTERN)
    until: str | None = Field(default=None, pattern=DATE_PATTERN)
    verified: bool | None = None
    has_cve: bool | None = None
    sort: str = "date"
    descending: bool = True
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=25, ge=1, le=500)


class Page[T](BaseModel):
    items: list[T]
    total: int
    page: int
    page_size: int

    @property
    def pages(self) -> int:
        return max(1, -(-self.total // self.page_size))


class DorkOperator(BaseModel):
    op: str
    value: str
    explanation: str


class DorkInput(BaseModel):
    username: str = ""
    target_domain: str = ""
    category: str = "profiles"
    exact_match: bool = True
    exclude_false_positives: bool = False
    restrict_domain: bool = True
    filetype: str | None = None
    include_phrases: list[str] = Field(default_factory=list)
    exclude_phrases: list[str] = Field(default_factory=list)
    custom_query: str = ""


class DorkQuery(BaseModel):
    id: str
    label: str
    category: str
    target_domain: str
    username: str
    query: str
    operators: list[DorkOperator] = Field(default_factory=list)
    explanation: str
    risk_level: str = "low"
    requires_authorization: bool = True
    warnings: list[str] = Field(default_factory=list)
    google_url: str = ""


class TemplateBundle(BaseModel):
    id: str
    module_type: str
    module_class: str
    cve_id: str | None = None
    edb_id: int | None = None
    ruby: str
    markdown: str
    metadata: dict[str, Any]
    preflight: list[str]
