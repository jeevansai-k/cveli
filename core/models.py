from pydantic import BaseModel, Field


class CWEID(BaseModel):
    id: int
    name: str


class CVEModel(BaseModel):
    id: str
    summary: str
    severity: str | None = Field(
        default=None, pattern=r"^(Critical|High|Medium|Low|Info)$"
    )
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    vector: str | None = None
    published: str = Field(default="", pattern=r"^$|^\d{4}-\d{2}-\d{2}$")
    updated: str = Field(default="", pattern=r"^$|^\d{4}-\d{2}-\d{2}$")
    kev_date: str = Field(default="", pattern=r"^$|^\d{4}-\d{2}-\d{2}$")
    affected_products: list[dict] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    exploit_available: bool = False
    epss: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    vendor: str | None = None
    cwe: CWEID | None = None
    tags: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    fetched_at: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "CVEModel":
        return cls(**data)

    def to_dict(self) -> dict:
        return self.model_dump()
