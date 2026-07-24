import asyncio
import json

from app.models import Component
from app.service import analyze_bom
from app.vulnerabilities import VulnerabilityProvider, VulnerabilityScanResult


class CapturingProvider(VulnerabilityProvider):
    name = "capture"

    def __init__(self) -> None:
        self.components: list[Component] = []

    async def scan(self, components: list[Component]) -> VulnerabilityScanResult:
        self.components = components
        return VulnerabilityScanResult()


def test_scan_limit_is_applied_after_scannable_filtering() -> None:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "root"}},
        "components": [
            {"type": "library", "name": "not-scannable"},
            {"type": "library", "name": "a", "purl": "pkg:npm/a@1"},
            {"type": "library", "name": "b", "purl": "pkg:npm/b@1"},
            {"type": "library", "name": "c", "purl": "pkg:npm/c@1"},
        ],
    }
    provider = CapturingProvider()

    report = asyncio.run(
        analyze_bom(
            json.dumps(document).encode(),
            "limit.cdx.json",
            provider,
            max_scanned_components=2,
        )
    )

    assert [component.name for component in provider.components] == ["a", "b"]
    assert report.summary.component_count == 5
    assert report.summary.scannable_component_count == 3
    assert report.summary.scanned_component_count == 2
    assert report.summary.scan_limit == 2
    assert report.summary.scan_truncated is True
