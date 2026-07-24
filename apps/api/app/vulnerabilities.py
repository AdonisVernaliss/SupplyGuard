import asyncio
from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx
from cvss import CVSS2, CVSS3, CVSS4, CVSSError
from packageurl import PackageURL

from app.models import Component, Severity, Vulnerability
from app.version import APP_VERSION


class VulnerabilityProviderError(RuntimeError):
    """Raised when a vulnerability data provider cannot complete a scan."""


@dataclass(slots=True)
class VulnerabilityScanResult:
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    data_complete: bool = True
    detail_failure_count: int = 0
    detail_limit: int = 0
    details_truncated: bool = False


@dataclass(frozen=True, slots=True)
class SeverityAssessment:
    severity: Severity
    score: float | None = None
    vector: str | None = None
    source: str | None = None


class VulnerabilityProvider(ABC):
    name: str

    @abstractmethod
    async def scan(self, components: list[Component]) -> VulnerabilityScanResult:
        raise NotImplementedError


class DemoVulnerabilityProvider(VulnerabilityProvider):
    name = "demo-fixtures"

    _records: dict[tuple[str, str], dict[str, Any]] = {
        ("lodash", "4.17.20"): {
            "id": "GHSA-35jh-r3h4-6jhm",
            "severity": Severity.HIGH,
            "summary": "Command injection in lodash template handling",
            "aliases": ["CVE-2021-23337"],
            "fixed_versions": ["4.17.21"],
            "references": ["https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm"],
        },
        ("minimist", "1.2.5"): {
            "id": "GHSA-xvch-5gv4-984h",
            "severity": Severity.CRITICAL,
            "summary": "Prototype pollution in minimist",
            "aliases": ["CVE-2021-44906"],
            "fixed_versions": ["1.2.6"],
            "references": ["https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h"],
        },
    }

    async def scan(self, components: list[Component]) -> VulnerabilityScanResult:
        vulnerabilities: list[Vulnerability] = []
        for component in components:
            key = (component.name.lower(), component.version or "")
            record = self._records.get(key)
            if not record:
                continue
            vulnerabilities.append(
                Vulnerability(
                    component_ref=component.bom_ref,
                    component_name=component.name,
                    installed_version=component.version,
                    source="SupplyGuard demo fixture",
                    **record,
                )
            )
        return VulnerabilityScanResult(vulnerabilities=vulnerabilities)


class OsvVulnerabilityProvider(VulnerabilityProvider):
    name = "osv-live"

    def __init__(
        self,
        base_url: str,
        timeout_seconds: float,
        max_pages: int = 20,
        max_details: int = 1_000,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_pages = max(1, max_pages)
        self.max_details = max(1, max_details)
        self.transport = transport

    async def scan(self, components: list[Component]) -> VulnerabilityScanResult:
        scannable = [component for component in components if is_scannable_component(component)]
        if not scannable:
            return VulnerabilityScanResult()

        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout_seconds,
                headers={"User-Agent": f"SupplyGuard/{APP_VERSION}"},
                transport=self.transport,
            ) as client:
                component_vulnerability_ids, query_complete = await _query_vulnerability_ids(
                    client, scannable, self.max_pages
                )
                unique_ids = sorted(
                    {
                        vulnerability_id
                        for _, vulnerability_ids in component_vulnerability_ids
                        for vulnerability_id in vulnerability_ids
                    }
                )
                detail_ids = unique_ids[: self.max_details]
                details, detail_failure_count = await _fetch_details(client, detail_ids)
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise VulnerabilityProviderError(
                "OSV is unavailable or returned an invalid response."
            ) from exc

        vulnerabilities: list[Vulnerability] = []
        for component, vulnerability_ids in component_vulnerability_ids:
            for vulnerability_id in vulnerability_ids:
                detail = details.get(vulnerability_id, {"id": vulnerability_id})
                vulnerabilities.append(_to_vulnerability(component, detail))
        details_truncated = len(unique_ids) > len(detail_ids)
        return VulnerabilityScanResult(
            vulnerabilities=vulnerabilities,
            data_complete=(query_complete and detail_failure_count == 0 and not details_truncated),
            detail_failure_count=detail_failure_count,
            detail_limit=self.max_details,
            details_truncated=details_truncated,
        )


def is_scannable_component(component: Component) -> bool:
    return _query_for(component) is not None


def scannable_component_count(components: Iterable[Component]) -> int:
    return sum(1 for component in components if is_scannable_component(component))


def _query_for(component: Component) -> dict[str, Any] | None:
    if not component.purl:
        return None
    try:
        PackageURL.from_string(component.purl)
    except ValueError:
        return None
    return {"package": {"purl": component.purl}}


async def _query_vulnerability_ids(
    client: httpx.AsyncClient,
    components: list[Component],
    max_pages: int,
) -> tuple[list[tuple[Component, list[str]]], bool]:
    base_queries = [_query_for(component) for component in components]
    if any(query is None for query in base_queries):
        raise ValueError("OSV received an unscannable component.")

    vulnerability_ids: list[list[str]] = [[] for _ in components]
    pending: list[tuple[int, dict[str, Any], str | None]] = [
        (index, query, None) for index, query in enumerate(base_queries) if isinstance(query, dict)
    ]
    page = 0
    while pending:
        if page >= max_pages:
            return list(zip(components, vulnerability_ids, strict=True)), False

        queries: list[dict[str, Any]] = []
        for _, base_query, page_token in pending:
            query = dict(base_query)
            if page_token:
                query["page_token"] = page_token
            queries.append(query)

        response = await client.post("/v1/querybatch", json={"queries": queries})
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            raise ValueError("OSV querybatch response has no results array.")
        results = payload["results"]
        if len(results) != len(pending):
            raise ValueError("OSV querybatch result count does not match the request.")

        next_pending: list[tuple[int, dict[str, Any], str | None]] = []
        for (component_index, base_query, _), result in zip(pending, results, strict=True):
            if not isinstance(result, dict):
                raise ValueError("OSV querybatch returned a malformed result.")
            records = result.get("vulns", [])
            if not isinstance(records, list):
                raise ValueError("OSV querybatch returned malformed vulnerabilities.")
            vulnerability_ids[component_index].extend(
                str(record["id"])
                for record in records
                if isinstance(record, dict) and record.get("id")
            )
            vulnerability_ids[component_index] = list(
                dict.fromkeys(vulnerability_ids[component_index])
            )

            next_page_token = result.get("next_page_token")
            if next_page_token is not None and not isinstance(next_page_token, str):
                raise ValueError("OSV querybatch returned a malformed page token.")
            if next_page_token:
                next_pending.append((component_index, base_query, next_page_token))

        pending = next_pending
        page += 1

    return list(zip(components, vulnerability_ids, strict=True)), True


async def _fetch_details(
    client: httpx.AsyncClient, vulnerability_ids: list[str]
) -> tuple[dict[str, dict[str, Any]], int]:
    semaphore = asyncio.Semaphore(8)

    async def fetch(vulnerability_id: str) -> tuple[str, dict[str, Any] | None]:
        try:
            async with semaphore:
                response = await client.get(f"/v1/vulns/{vulnerability_id}")
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict):
                    raise ValueError("OSV vulnerability detail is not an object.")
                return vulnerability_id, payload
        except (httpx.HTTPError, ValueError, TypeError):
            return vulnerability_id, None

    details: dict[str, dict[str, Any]] = {}
    failure_count = 0
    for offset in range(0, len(vulnerability_ids), 100):
        batch = vulnerability_ids[offset : offset + 100]
        pairs = await asyncio.gather(*(fetch(item) for item in batch))
        for vulnerability_id, payload in pairs:
            if payload is None:
                failure_count += 1
            else:
                details[vulnerability_id] = payload
    return details, failure_count


def _to_vulnerability(component: Component, detail: dict[str, Any]) -> Vulnerability:
    vulnerability_id = str(detail.get("id") or "UNKNOWN")
    aliases = [str(item) for item in detail.get("aliases", []) if isinstance(item, str)]
    references = [
        str(item["url"])
        for item in detail.get("references", [])
        if isinstance(item, dict) and isinstance(item.get("url"), str)
    ][:5]
    assessment = _severity(detail, component)
    return Vulnerability(
        id=vulnerability_id,
        component_ref=component.bom_ref,
        component_name=component.name,
        installed_version=component.version,
        severity=assessment.severity,
        cvss_score=assessment.score,
        cvss_vector=assessment.vector,
        severity_source=assessment.source,
        summary=str(detail.get("summary") or detail.get("details") or vulnerability_id)[:500],
        aliases=aliases,
        fixed_versions=_fixed_versions(detail, component),
        references=references,
        source="OSV",
    )


def _severity(detail: dict[str, Any], component: Component) -> SeverityAssessment:
    matching_affected = _matching_affected(detail, component)

    affected_cvss = _best_cvss_assessment(
        [item for affected in matching_affected for item in _severity_items(affected)],
        "OSV affected",
    )
    if affected_cvss:
        return affected_cvss

    top_level_cvss = _best_cvss_assessment(_severity_items(detail), "OSV")
    if top_level_cvss:
        return top_level_cvss

    qualitative: list[SeverityAssessment] = []
    for affected in matching_affected:
        for metadata_field in ("ecosystem_specific", "database_specific"):
            assessment = _qualitative_assessment(
                affected.get(metadata_field), f"affected.{metadata_field}"
            )
            if assessment:
                qualitative.append(assessment)
    top_level = _qualitative_assessment(detail.get("database_specific"), "database_specific")
    if top_level:
        qualitative.append(top_level)
    if qualitative:
        return max(qualitative, key=lambda item: _severity_rank(item.severity))
    return SeverityAssessment(Severity.UNKNOWN)


def _best_cvss_assessment(
    items: Sequence[dict[str, Any]], source_prefix: str
) -> SeverityAssessment | None:
    assessments: list[SeverityAssessment] = []
    calculators = {"CVSS_V2": CVSS2, "CVSS_V3": CVSS3, "CVSS_V4": CVSS4}
    for item in items:
        severity_type = item.get("type")
        vector = item.get("score")
        calculator = calculators.get(severity_type)
        if calculator is None or not isinstance(vector, str):
            continue
        try:
            parsed = calculator(vector)
            score = float(parsed.scores()[0])
            label = str(parsed.severities()[0])
        except (CVSSError, ValueError, TypeError, IndexError):
            continue
        severity = _normalize_severity(label)
        if severity is Severity.UNKNOWN:
            continue
        source = item.get("source")
        suffix = f":{source}" if isinstance(source, str) and source else ""
        assessments.append(
            SeverityAssessment(
                severity=severity,
                score=score,
                vector=vector,
                source=f"{source_prefix} {severity_type}{suffix}",
            )
        )
    if not assessments:
        return None
    return max(
        assessments,
        key=lambda item: (_severity_rank(item.severity), item.score or 0.0),
    )


def _severity_items(container: dict[str, Any]) -> list[dict[str, Any]]:
    items = container.get("severity")
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def _qualitative_assessment(value: Any, source: str) -> SeverityAssessment | None:
    if not isinstance(value, dict):
        return None
    severity = _normalize_severity(value.get("severity"))
    if severity is Severity.UNKNOWN:
        return None
    return SeverityAssessment(severity=severity, source=source)


def _normalize_severity(value: Any) -> Severity:
    normalized = str(value or "").strip().lower()
    aliases = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "important": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "moderate": Severity.MEDIUM,
        "low": Severity.LOW,
        "negligible": Severity.LOW,
    }
    return aliases.get(normalized, Severity.UNKNOWN)


def _severity_rank(severity: Severity) -> int:
    return {
        Severity.UNKNOWN: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }[severity]


def _fixed_versions(detail: dict[str, Any], component: Component) -> list[str]:
    fixed: set[str] = set()
    for affected in _matching_affected(detail, component):
        ranges = affected.get("ranges", [])
        if not isinstance(ranges, list):
            continue
        for version_range in ranges:
            if not isinstance(version_range, dict):
                continue
            events = version_range.get("events", [])
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed.add(event["fixed"])
    return sorted(fixed)


def _matching_affected(detail: dict[str, Any], component: Component) -> list[dict[str, Any]]:
    affected_items = detail.get("affected")
    if not isinstance(affected_items, list):
        return []
    return [
        affected
        for affected in affected_items
        if isinstance(affected, dict) and _affected_matches_component(affected, component)
    ]


def _affected_matches_component(affected: dict[str, Any], component: Component) -> bool:
    package = affected.get("package")
    if not isinstance(package, dict) or not component.purl:
        return False

    component_identity = _purl_identity(component.purl)
    affected_purl = package.get("purl")
    if isinstance(affected_purl, str):
        return component_identity is not None and component_identity == _purl_identity(
            affected_purl
        )

    try:
        parsed = PackageURL.from_string(component.purl)
    except ValueError:
        return False
    ecosystem = str(package.get("ecosystem") or "").casefold()
    expected_ecosystem = {
        "cargo": "crates.io",
        "composer": "packagist",
        "gem": "rubygems",
        "golang": "go",
        "pypi": "pypi",
    }.get(parsed.type.casefold(), parsed.type.casefold())
    if ecosystem.split(":", 1)[0] != expected_ecosystem:
        return False

    name = str(package.get("name") or "").casefold()
    component_names = {parsed.name.casefold()}
    if parsed.namespace:
        namespace = parsed.namespace.casefold()
        component_names.update(
            {f"{namespace}/{parsed.name.casefold()}", f"{namespace}:{parsed.name.casefold()}"}
        )
    return name in component_names


def _purl_identity(value: str) -> tuple[str, str, str] | None:
    try:
        parsed = PackageURL.from_string(value)
    except ValueError:
        return None
    return (
        parsed.type.casefold(),
        (parsed.namespace or "").casefold(),
        parsed.name.casefold(),
    )
