from pydantic import BaseModel, field_validator
from typing import List, Optional


class CWEEntry(BaseModel):
    id: str
    name: str
    description: str
    related_weaknesses: List[dict] = []

    @field_validator("id")
    @classmethod
    def id_must_be_numeric(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit():
            raise ValueError("CWE id must be a numeric string")
        return v

    @field_validator("name", "description")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        return v.strip()


VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}


class CVSSScores(BaseModel):
    v2_score: Optional[float] = None
    v2_vector: Optional[str] = None
    v3_score: Optional[float] = None
    v3_vector: Optional[str] = None
    v3_severity: Optional[str] = None

    @field_validator("v2_score", "v3_score")
    @classmethod
    def score_in_range(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and not (0.0 <= v <= 10.0):
            raise ValueError("CVSS score must be between 0.0 and 10.0")
        return v

    @field_validator("v3_severity")
    @classmethod
    def severity_must_be_valid(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.upper() not in VALID_SEVERITIES:
            raise ValueError(
                f"Severity must be one of: {', '.join(VALID_SEVERITIES)}"
            )
        return v.upper() if v else v


class AffectedProduct(BaseModel):
    vendor: str
    product: str
    version: str


class Reference(BaseModel):
    url: str
    source: Optional[str] = None
    tags: List[str] = []

    @field_validator("url")
    @classmethod
    def url_must_be_valid(cls, v: str) -> str:
        v = v.strip()
        if not (v.startswith("https://") or v.startswith("http://")):
            raise ValueError("Reference URL must start with http:// or https://")
        return v


class CVEDetail(BaseModel):
    cve_id: str
    description: str
    cvss: CVSSScores
    cwe_ids: List[str] = []
    references: List[Reference] = []
    affected_products: List[AffectedProduct] = []
    published: str
    modified: str


class CVESearchResult(BaseModel):
    cve_id: str
    description: str
    severity: Optional[str] = None
    cvss_v3: Optional[float] = None
    cwe_ids: List[str] = []
    published: str


class CWEStats(BaseModel):
    cwe_id: str
    cwe_name: str
    cve_count: int


class CWERiskScore(BaseModel):
    cwe_id: str
    cwe_name: str
    cve_count: int
    avg_cvss: float
    risk_score: float
