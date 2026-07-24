from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class ApiModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class FindingLevel(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ComplianceProfile(ApiModel):
    id: str
    version: str
    format: str
    mapping_version: str
    minimum_spec_version: str
    reference_url: str


class ValidationFinding(ApiModel):
    code: str
    level: FindingLevel
    message_key: str
    path: str
    params: dict[str, Any] = Field(default_factory=dict)


class Component(ApiModel):
    bom_ref: str | None = None
    name: str
    version: str | None = None
    component_type: str = "library"
    group: str | None = None
    purl: str | None = None
    creator: str | None = None
    filename: str | None = None
    licenses: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)
    executable: str | None = None
    archive: str | None = None
    structured: str | None = None
    relationship: str = "unknown"


class Vulnerability(ApiModel):
    id: str
    component_ref: str | None = None
    component_name: str
    installed_version: str | None = None
    severity: Severity = Severity.UNKNOWN
    summary: str
    aliases: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    source: str = "OSV"


class DocumentMetadata(ApiModel):
    filename: str
    bom_format: str | None = None
    spec_version: str | None = None
    serial_number: str | None = None
    timestamp: str | None = None
    root_component: str | None = None


class AnalysisSummary(ApiModel):
    component_count: int
    scannable_component_count: int
    vulnerability_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    unknown_count: int
    validation_error_count: int
    validation_warning_count: int
    compliance_score: int
    risk_score: int


class AnalysisReport(ApiModel):
    id: str
    created_at: datetime
    provider: str
    profile: ComplianceProfile
    document: DocumentMetadata
    summary: AnalysisSummary
    findings: list[ValidationFinding]
    components: list[Component]
    vulnerabilities: list[Vulnerability]


class AnalysisListItem(ApiModel):
    id: str
    created_at: datetime
    filename: str
    provider: str
    component_count: int
    vulnerability_count: int
    compliance_score: int
    risk_score: int


class HealthResponse(ApiModel):
    status: str
    version: str
    supported_profile: ComplianceProfile
