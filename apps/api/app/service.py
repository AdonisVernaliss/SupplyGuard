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
from app.validator import compliance_score, validate_bom
from app.vulnerabilities import VulnerabilityProvider, scannable_component_count


async def analyze_bom(
    payload: bytes,
    filename: str,
    provider: VulnerabilityProvider,
    max_scanned_components: int,
) -> AnalysisReport:
    document = parse_json_bom(payload)
    components = extract_components(document)
    findings = validate_bom(document, components)
    scan_targets = components[:max_scanned_components]
    vulnerabilities = await provider.scan(scan_targets)

    return AnalysisReport(
        id=str(uuid4()),
        created_at=datetime.now(UTC),
        provider=provider.name,
        profile=supported_profile(),
        document=extract_document_metadata(document, filename),
        summary=_summary(components, findings, vulnerabilities),
        findings=findings,
        components=components,
        vulnerabilities=vulnerabilities,
    )


def demo_bom_bytes() -> bytes:
    repository_root = Path(__file__).resolve().parents[3]
    return (repository_root / "samples" / "demo-shop.cdx.json").read_bytes()


def _summary(components, findings, vulnerabilities: list[Vulnerability]) -> AnalysisSummary:
    severity_counts = {
        severity: sum(1 for item in vulnerabilities if item.severity == severity)
        for severity in Severity
    }
    return AnalysisSummary(
        component_count=len(components),
        scannable_component_count=scannable_component_count(components),
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
