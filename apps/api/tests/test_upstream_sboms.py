import asyncio
import hashlib
from pathlib import Path

import pytest

from app.parser import parse_json_bom
from app.schema_validation import validate_cyclonedx_schema
from app.service import analyze_bom
from app.vulnerabilities import DemoVulnerabilityProvider

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "upstream"
UPSTREAM_FIXTURES = [
    (
        "component-identifiers-1.6.json",
        "1.6",
        "36b69828f19416ff323502c37077529cfd7a8276a56bb7c49684c58d6e07cbff",
    ),
    (
        "min-required-1.7.json",
        "1.7",
        "01d0cafbed5b2051082bdfd1480f9f6615e9592bfd9fbf3baff01642f2741a8a",
    ),
]


@pytest.mark.parametrize(("filename", "spec_version", "sha256"), UPSTREAM_FIXTURES)
def test_pinned_upstream_sbom_passes_schema_and_analysis(
    filename: str, spec_version: str, sha256: str
) -> None:
    payload = (FIXTURE_DIR / filename).read_bytes()
    assert hashlib.sha256(payload).hexdigest() == sha256

    document = parse_json_bom(payload)
    assert document["specVersion"] == spec_version
    assert validate_cyclonedx_schema(document) == []

    report = asyncio.run(
        analyze_bom(
            payload,
            filename,
            DemoVulnerabilityProvider(),
            max_scanned_components=200,
        )
    )
    assert report.document.spec_version == spec_version
    assert report.profile.version == "2.1.0"
