from typing import List, Literal, Optional
from pydantic import BaseModel

# Levels for individual issues
LevelType = Literal["good", "info", "warning", "critical"]

# Overall risk level for the whole site
RiskLevelType = Literal["low", "medium", "high", "critical"]


class ScanRequest(BaseModel):
    """API input: which URL to scan."""
    url: str


class Issue(BaseModel):
    """Single security issue or info for a page."""
    level: LevelType          # good / info / warning / critical
    title: str                # short name of issue
    detail: str               # explanation in simple language
    page: Optional[str] = None  # which page this belongs to (URL)


class PageSummary(BaseModel):
    """Summary for each scanned page."""
    url: str
    status: int
    issues: List[Issue]


class DnsInfo(BaseModel):
    """DNS / WHOIS information."""
    domain: str
    has_dns: bool
    nameservers: List[str]
    has_whois: bool
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None


class IssueStats(BaseModel):
    """Count of issues by level for the whole scan."""
    total: int
    good: int
    info: int
    warning: int
    critical: int


class TopIssue(BaseModel):
    """Grouped summary of repeated issues."""
    title: str
    level: LevelType
    count: int
    example_page: Optional[str] = None


class ScanResult(BaseModel):
    """Full scan result returned by API."""
    root_url: str
    total_pages_scanned: int
    response_time_ms: float
    redirect_count: int
    pages: List[PageSummary]
    dns_info: Optional[DnsInfo] = None

    # High-level analytics
    stats: IssueStats                # total count per level
    overall_risk: RiskLevelType      # low / medium / high / critical
    risk_score: int                  # 0–100 simple risk score
    top_issues: List[TopIssue]       # grouped summary
