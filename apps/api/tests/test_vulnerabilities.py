import asyncio
import json

import httpx

from app.models import Component, Severity
from app.vulnerabilities import OsvVulnerabilityProvider, _to_vulnerability


def _component() -> Component:
    return Component(
        bom_ref="pkg:npm/lodash@4.17.20",
        name="lodash",
        version="4.17.20",
        purl="pkg:npm/lodash@4.17.20",
    )


def test_cvss_and_fixed_versions_are_package_specific() -> None:
    detail = {
        "id": "GHSA-test",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "other-package"},
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                ],
                "ranges": [{"events": [{"fixed": "99.0.0"}]}],
            },
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N",
                    }
                ],
                "ranges": [{"events": [{"fixed": "4.17.21"}]}],
            },
        ],
    }

    vulnerability = _to_vulnerability(_component(), detail)

    assert vulnerability.severity == Severity.MEDIUM
    assert vulnerability.cvss_score == 5.9
    assert vulnerability.fixed_versions == ["4.17.21"]


def test_top_level_cvss_and_moderate_fallback_are_normalized() -> None:
    cvss = _to_vulnerability(
        _component(),
        {
            "id": "GHSA-cvss",
            "severity": [
                {
                    "type": "CVSS_V4",
                    "score": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N"),
                }
            ],
        },
    )
    moderate = _to_vulnerability(
        _component(),
        {"id": "GHSA-moderate", "database_specific": {"severity": "MODERATE"}},
    )

    assert cvss.severity == Severity.CRITICAL
    assert cvss.cvss_score is not None
    assert moderate.severity == Severity.MEDIUM


def test_osv_pagination_is_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            query = json.loads(request.content)["queries"][0]
            if query.get("page_token") == "page-2":
                return httpx.Response(200, json={"results": [{"vulns": [{"id": "OSV-2"}]}]})
            return httpx.Response(
                200,
                json={"results": [{"vulns": [{"id": "OSV-1"}], "next_page_token": "page-2"}]},
            )
        vulnerability_id = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json={"id": vulnerability_id, "summary": vulnerability_id})

    provider = OsvVulnerabilityProvider(
        "https://api.osv.test",
        timeout_seconds=1,
        transport=httpx.MockTransport(handler),
    )
    result = asyncio.run(provider.scan([_component()]))

    assert [item.id for item in result.vulnerabilities] == ["OSV-1", "OSV-2"]
    assert result.data_complete is True
    assert result.detail_failure_count == 0


def test_osv_detail_failure_returns_marked_partial_result() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(
                200,
                json={"results": [{"vulns": [{"id": "OSV-ok"}, {"id": "OSV-failed"}]}]},
            )
        if request.url.path.endswith("OSV-failed"):
            return httpx.Response(503)
        return httpx.Response(200, json={"id": "OSV-ok", "summary": "Known detail"})

    provider = OsvVulnerabilityProvider(
        "https://api.osv.test",
        timeout_seconds=1,
        transport=httpx.MockTransport(handler),
    )
    result = asyncio.run(provider.scan([_component()]))

    assert len(result.vulnerabilities) == 2
    assert result.data_complete is False
    assert result.detail_failure_count == 1
    assert (
        next(item for item in result.vulnerabilities if item.id == "OSV-failed").severity
        == Severity.UNKNOWN
    )


def test_osv_detail_limit_is_explicit_and_marks_partial_data() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(
                200,
                json={"results": [{"vulns": [{"id": "OSV-1"}, {"id": "OSV-2"}]}]},
            )
        vulnerability_id = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json={"id": vulnerability_id})

    provider = OsvVulnerabilityProvider(
        "https://api.osv.test",
        timeout_seconds=1,
        max_details=1,
        transport=httpx.MockTransport(handler),
    )
    result = asyncio.run(provider.scan([_component()]))

    assert result.data_complete is False
    assert result.detail_limit == 1
    assert result.details_truncated is True
    assert len(result.vulnerabilities) == 2
