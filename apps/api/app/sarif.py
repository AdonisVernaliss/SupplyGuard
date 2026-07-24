from typing import Any
from urllib.parse import quote

from app.localization import localize_finding
from app.models import AnalysisReport, FindingLevel, Severity
from app.version import APP_VERSION

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def sarif_report(report: AnalysisReport, language: str = "en") -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    artifact_uri = quote(report.document.filename)

    for finding in report.findings:
        message = localize_finding(finding, language)
        rules.setdefault(
            finding.code,
            {
                "id": finding.code,
                "name": finding.message_key,
                "shortDescription": {"text": message},
                "helpUri": report.profile.reference_url,
                "properties": {
                    "category": "compliance",
                    "profile": f"{report.profile.id} {report.profile.version}",
                },
            },
        )
        results.append(
            {
                "ruleId": finding.code,
                "level": _finding_level(finding.level),
                "message": {"text": message},
                "locations": [_location(artifact_uri, finding.path)],
                "properties": {
                    "category": "compliance",
                    "findingLevel": finding.level.value,
                    "jsonPath": finding.path,
                },
            }
        )

    for vulnerability in report.vulnerabilities:
        rules.setdefault(
            vulnerability.id,
            {
                "id": vulnerability.id,
                "name": vulnerability.id,
                "shortDescription": {"text": vulnerability.summary},
                **({"helpUri": vulnerability.references[0]} if vulnerability.references else {}),
                "properties": {
                    "category": "vulnerability",
                    "severity": vulnerability.severity.value,
                    "source": vulnerability.source,
                },
            },
        )
        results.append(
            {
                "ruleId": vulnerability.id,
                "level": _vulnerability_level(vulnerability.severity),
                "message": {
                    "text": (
                        f"{vulnerability.component_name}: {vulnerability.summary} "
                        f"(severity: {vulnerability.severity.value})"
                    )
                },
                "locations": [_location(artifact_uri, vulnerability.component_ref)],
                "properties": {
                    "category": "vulnerability",
                    "component": vulnerability.component_name,
                    "componentRef": vulnerability.component_ref,
                    "installedVersion": vulnerability.installed_version,
                    "severity": vulnerability.severity.value,
                    "cvssScore": vulnerability.cvss_score,
                    "cvssVector": vulnerability.cvss_vector,
                    "fixedVersions": vulnerability.fixed_versions,
                    "dataComplete": report.summary.vulnerability_data_complete,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SupplyGuard",
                        "semanticVersion": APP_VERSION,
                        "rules": list(rules.values()),
                    }
                },
                "artifacts": [{"location": {"uri": artifact_uri}}],
                "results": results,
                "properties": {
                    "analysisId": report.id,
                    "provider": report.provider,
                    "profile": report.profile.model_dump(mode="json", by_alias=True),
                    "summary": report.summary.model_dump(mode="json", by_alias=True),
                },
            }
        ],
    }


def _location(artifact_uri: str, logical_name: str | None) -> dict[str, Any]:
    location: dict[str, Any] = {"physicalLocation": {"artifactLocation": {"uri": artifact_uri}}}
    if logical_name:
        location["logicalLocations"] = [{"fullyQualifiedName": logical_name, "kind": "jsonPath"}]
    return location


def _finding_level(level: FindingLevel) -> str:
    return {
        FindingLevel.ERROR: "error",
        FindingLevel.WARNING: "warning",
        FindingLevel.INFO: "note",
    }[level]


def _vulnerability_level(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.UNKNOWN: "note",
    }[severity]
