import asyncio
import json

from app.sarif import SARIF_SCHEMA, sarif_report
from app.service import analyze_bom, demo_bom_bytes
from app.vulnerabilities import DemoVulnerabilityProvider


def test_sarif_contains_rules_locations_and_scan_metadata() -> None:
    report = asyncio.run(
        analyze_bom(
            demo_bom_bytes(),
            "demo shop.cdx.json",
            DemoVulnerabilityProvider(),
            max_scanned_components=200,
        )
    )

    payload = sarif_report(report, "ru")
    run = payload["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]

    assert payload["$schema"] == SARIF_SCHEMA
    assert run["artifacts"][0]["location"]["uri"] == "demo%20shop.cdx.json"
    assert len(rules) == len({result["ruleId"] for result in results})
    assert run["properties"]["profile"]["version"] == "2.1.0"
    assert run["properties"]["summary"]["vulnerabilityDataComplete"] is True
    assert any(result["ruleId"] == "GHSA-35jh-r3h4-6jhm" for result in results)


def test_sarif_localizes_profile_findings() -> None:
    payload = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}).encode()
    report = asyncio.run(
        analyze_bom(
            payload,
            "invalid.cdx.json",
            DemoVulnerabilityProvider(),
            max_scanned_components=200,
        )
    )

    results = sarif_report(report, "ru")["runs"][0]["results"]
    timestamp = next(result for result in results if result["ruleId"] == "SG004")

    assert timestamp["level"] == "error"
    assert "время создания SBOM" in timestamp["message"]["text"]
    assert timestamp["properties"]["jsonPath"] == "$.metadata.timestamp"
