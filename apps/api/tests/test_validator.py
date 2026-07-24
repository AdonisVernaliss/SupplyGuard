import json
from pathlib import Path

from app.parser import extract_components
from app.schema_validation import validate_cyclonedx_schema
from app.validator import compliance_score, validate_bom

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def test_profile_complete_demo_scores_100() -> None:
    complete = json.loads((REPOSITORY_ROOT / "samples" / "demo-shop.cdx.json").read_text())
    findings = validate_bom(complete, extract_components(complete))

    assert findings == []
    assert compliance_score(findings) == 100


def test_old_profile_and_incomplete_document_are_rejected() -> None:
    incomplete = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"name": "lodash"}],
    }
    findings = validate_bom(incomplete, extract_components(incomplete))

    assert any(finding.code == "SG002" for finding in findings)
    assert any(finding.code == "SG005" for finding in findings)
    assert compliance_score(findings) < 50


def test_vulnerabilities_must_not_be_embedded_in_sbom() -> None:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "vulnerabilities": [{"id": "CVE-2026-0001"}],
    }
    findings = validate_bom(document, [])

    assert any(finding.code == "SG007" for finding in findings)


def test_malformed_composition_does_not_crash_validation() -> None:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "compositions": [{"aggregate": "complete", "assemblies": "not-a-list", "dependencies": []}],
    }

    findings = validate_bom(document, [])

    assert isinstance(findings, list)


def test_supported_cyclonedx_schema_is_validated_at_runtime() -> None:
    document = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": "invalid"}

    findings = validate_cyclonedx_schema(document)

    assert findings
    assert all(finding.code == "SG008" for finding in findings)
