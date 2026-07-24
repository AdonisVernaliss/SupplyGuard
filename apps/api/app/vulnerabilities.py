import asyncio
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any

import httpx

from app.models import Component, Severity, Vulnerability


class VulnerabilityProviderError(RuntimeError):
    """Raised when a vulnerability data provider cannot complete a scan."""


class VulnerabilityProvider(ABC):
    name: str

    @abstractmethod
    async def scan(self, components: list[Component]) -> list[Vulnerability]:
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

    async def scan(self, components: list[Component]) -> list[Vulnerability]:
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
        return vulnerabilities


class OsvVulnerabilityProvider(VulnerabilityProvider):
    name = "osv-live"

    def __init__(self, base_url: str, timeout_seconds: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    async def scan(self, components: list[Component]) -> list[Vulnerability]:
        scannable = [component for component in components if _query_for(component)]
        if not scannable:
            return []

        queries = [_query_for(component) for component in scannable]
        try:
            async with httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self.timeout_seconds,
                headers={"User-Agent": "SupplyGuard/0.1"},
            ) as client:
                response = await client.post("/v1/querybatch", json={"queries": queries})
                response.raise_for_status()
                results = response.json().get("results", [])
                component_vulnerability_ids = _component_vulnerability_ids(scannable, results)
                unique_ids = sorted(
                    {
                        vulnerability_id
                        for _, vulnerability_ids in component_vulnerability_ids
                        for vulnerability_id in vulnerability_ids
                    }
                )[:100]
                details = await _fetch_details(client, unique_ids)
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise VulnerabilityProviderError(
                "OSV is unavailable or returned an invalid response."
            ) from exc

        vulnerabilities: list[Vulnerability] = []
        for component, vulnerability_ids in component_vulnerability_ids:
            for vulnerability_id in vulnerability_ids:
                detail = details.get(vulnerability_id, {"id": vulnerability_id})
                vulnerabilities.append(_to_vulnerability(component, detail))
        return vulnerabilities


def scannable_component_count(components: Iterable[Component]) -> int:
    return sum(1 for component in components if _query_for(component))


def _query_for(component: Component) -> dict[str, Any] | None:
    if component.purl:
        return {"package": {"purl": component.purl}}
    return None


def _component_vulnerability_ids(
    components: list[Component], results: list[Any]
) -> list[tuple[Component, list[str]]]:
    mapped: list[tuple[Component, list[str]]] = []
    for index, component in enumerate(components):
        result = results[index] if index < len(results) and isinstance(results[index], dict) else {}
        records = result.get("vulns") if isinstance(result.get("vulns"), list) else []
        mapped.append(
            (
                component,
                [
                    str(record["id"])
                    for record in records
                    if isinstance(record, dict) and record.get("id")
                ],
            )
        )
    return mapped


async def _fetch_details(
    client: httpx.AsyncClient, vulnerability_ids: list[str]
) -> dict[str, dict[str, Any]]:
    semaphore = asyncio.Semaphore(8)

    async def fetch(vulnerability_id: str) -> tuple[str, dict[str, Any]]:
        async with semaphore:
            response = await client.get(f"/v1/vulns/{vulnerability_id}")
            response.raise_for_status()
            payload = response.json()
            return vulnerability_id, payload if isinstance(payload, dict) else {}

    pairs = await asyncio.gather(*(fetch(item) for item in vulnerability_ids))
    return dict(pairs)


def _to_vulnerability(component: Component, detail: dict[str, Any]) -> Vulnerability:
    vulnerability_id = str(detail.get("id") or "UNKNOWN")
    aliases = [str(item) for item in detail.get("aliases", []) if isinstance(item, str)]
    references = [
        str(item["url"])
        for item in detail.get("references", [])
        if isinstance(item, dict) and isinstance(item.get("url"), str)
    ][:5]
    return Vulnerability(
        id=vulnerability_id,
        component_ref=component.bom_ref,
        component_name=component.name,
        installed_version=component.version,
        severity=_severity(detail),
        summary=str(detail.get("summary") or detail.get("details") or vulnerability_id)[:500],
        aliases=aliases,
        fixed_versions=_fixed_versions(detail),
        references=references,
        source="OSV",
    )


def _severity(detail: dict[str, Any]) -> Severity:
    database_specific = detail.get("database_specific")
    if isinstance(database_specific, dict):
        value = str(database_specific.get("severity") or "").lower()
        if value in {item.value for item in Severity}:
            return Severity(value)

    ecosystem_severities: list[str] = []
    for affected in detail.get("affected", []):
        if not isinstance(affected, dict):
            continue
        ecosystem_specific = affected.get("ecosystem_specific")
        if isinstance(ecosystem_specific, dict):
            value = ecosystem_specific.get("severity")
            if isinstance(value, str):
                ecosystem_severities.append(value.lower())
    for candidate in ("critical", "high", "medium", "low"):
        if candidate in ecosystem_severities:
            return Severity(candidate)
    return Severity.UNKNOWN


def _fixed_versions(detail: dict[str, Any]) -> list[str]:
    fixed: set[str] = set()
    for affected in detail.get("affected", []):
        if not isinstance(affected, dict):
            continue
        for version_range in affected.get("ranges", []):
            if not isinstance(version_range, dict):
                continue
            for event in version_range.get("events", []):
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed.add(event["fixed"])
    return sorted(fixed)
