from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from app.models import (
    AnalysisReport,
    AnalysisSummary,
    FindingLevel,
    Severity,
    Vulnerability,
)
from app.parser import extract_components, extract_document_metadata, parse_json_bom
from app.profile import supported_profile
from app.schema_validation import validate_cyclonedx_schema
from app.validator import compliance_score, validate_bom
from app.vulnerabilities import (
    VulnerabilityProvider,
    is_scannable_component,
    scannable_component_count,
)


async def analyze_bom(
    payload: bytes,
    filename: str,
    provider: VulnerabilityProvider,
    max_scanned_components: int,
    max_component_count: int = 10_000,
    max_component_depth: int = 100,
) -> AnalysisReport:
    document = parse_json_bom(payload)
    components = extract_components(
        document,
        max_component_count=max_component_count,
        max_component_depth=max_component_depth,
    )
    findings = [
        *validate_cyclonedx_schema(document),
        *validate_bom(
            document,
            components,
            max_component_count=max_component_count,
            max_component_depth=max_component_depth,
        ),
    ]
    scannable = [component for component in components if is_scannable_component(component)]
    scan_targets = scannable[:max_scanned_components]
    scan_result = await provider.scan(scan_targets)

    return AnalysisReport(
        id=str(uuid4()),
        created_at=datetime.now(UTC),
        provider=provider.name,
        profile=supported_profile(),
        document=extract_document_metadata(document, filename),
        summary=_summary(
            components,
            findings,
            scan_result.vulnerabilities,
            scanned_component_count=len(scan_targets),
            scan_limit=max_scanned_components,
            scan_truncated=len(scannable) > len(scan_targets),
            vulnerability_data_complete=scan_result.data_complete,
            vulnerability_detail_failure_count=scan_result.detail_failure_count,
            vulnerability_detail_limit=scan_result.detail_limit,
            vulnerability_details_truncated=scan_result.details_truncated,
        ),
        findings=findings,
        components=components,
        vulnerabilities=scan_result.vulnerabilities,
    )


def demo_bom_bytes() -> bytes:
    repository_root = Path(__file__).resolve().parents[3]
    return (repository_root / "samples" / "demo-shop.cdx.json").read_bytes()


def _summary(
    components,
    findings,
    vulnerabilities: list[Vulnerability],
    scanned_component_count: int,
    scan_limit: int,
    scan_truncated: bool,
    vulnerability_data_complete: bool,
    vulnerability_detail_failure_count: int,
    vulnerability_detail_limit: int,
    vulnerability_details_truncated: bool,
) -> AnalysisSummary:
    severity_counts = {
        severity: sum(1 for item in vulnerabilities if item.severity == severity)
        for severity in Severity
    }
    return AnalysisSummary(
        component_count=len(components),
        scannable_component_count=scannable_component_count(components),
        scanned_component_count=scanned_component_count,
        scan_limit=scan_limit,
        scan_truncated=scan_truncated,
        vulnerability_data_complete=vulnerability_data_complete,
        vulnerability_detail_failure_count=vulnerability_detail_failure_count,
        vulnerability_detail_limit=vulnerability_detail_limit,
        vulnerability_details_truncated=vulnerability_details_truncated,
        vulnerability_count=len(vulnerabilities),
        critical_count=severity_counts[Severity.CRITICAL],
        high_count=severity_counts[Severity.HIGH],
        medium_count=severity_counts[Severity.MEDIUM],
        low_count=severity_counts[Severity.LOW],
        unknown_count=severity_counts[Severity.UNKNOWN],
        validation_error_count=sum(
            1 for finding in findings if finding.level == FindingLevel.ERROR
        ),
        validation_warning_count=sum(
            1 for finding in findings if finding.level == FindingLevel.WARNING
        ),
        compliance_score=compliance_score(findings),
        risk_score=_risk_score(vulnerabilities),
    )


def _risk_score(vulnerabilities: list[Vulnerability]) -> int:
    weights = {
        Severity.CRITICAL: 30,
        Severity.HIGH: 18,
        Severity.MEDIUM: 9,
        Severity.LOW: 3,
        Severity.UNKNOWN: 5,
    }
    return min(100, sum(weights[item.severity] for item in vulnerabilities))
