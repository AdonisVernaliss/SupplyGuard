import re
from collections import Counter
from typing import Any

from app.models import Component, FindingLevel, ValidationFinding
from app.parser import raw_components_with_paths
from app.profile import (
    MINIMUM_CYCLONEDX_VERSION,
    PROFILE_VERSION,
    SUPPORTED_CYCLONEDX_VERSIONS,
)

UUID_URN = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
BSI_PROPERTY_VALUES = {
    "bsi:component:executable": {"executable", "non-executable"},
    "bsi:component:archive": {"archive", "no archive"},
    "bsi:component:structured": {"structured", "unstructured"},
}


def validate_bom(document: dict[str, Any], components: list[Component]) -> list[ValidationFinding]:
    """Validate the CycloneDX mapping defined by BSI TR-03183-2 v2.1.0.

    The BSI mapping is based on CycloneDX 1.6. SupplyGuard also accepts 1.7
    documents where the mapped fields retain the same semantics.
    """

    findings: list[ValidationFinding] = []
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}

    if document.get("bomFormat") != "CycloneDX":
        findings.append(_finding("SG001", FindingLevel.ERROR, "finding.bomFormat", "$.bomFormat"))

    spec_version = document.get("specVersion")
    if spec_version not in SUPPORTED_CYCLONEDX_VERSIONS:
        findings.append(
            _finding(
                "SG002",
                FindingLevel.ERROR,
                "finding.specVersion",
                "$.specVersion",
                {
                    "minimum": MINIMUM_CYCLONEDX_VERSION,
                    "profile": PROFILE_VERSION,
                    "supported": ", ".join(sorted(SUPPORTED_CYCLONEDX_VERSIONS)),
                },
            )
        )

    serial_number = document.get("serialNumber")
    if isinstance(serial_number, str) and not UUID_URN.match(serial_number):
        findings.append(
            _finding(
                "SG003",
                FindingLevel.WARNING,
                "finding.serialNumberInvalid",
                "$.serialNumber",
            )
        )

    if not isinstance(metadata.get("timestamp"), str):
        findings.append(
            _finding(
                "SG004",
                FindingLevel.ERROR,
                "finding.timestampMissing",
                "$.metadata.timestamp",
            )
        )

    if not _has_creator(metadata):
        findings.append(
            _finding(
                "SG005",
                FindingLevel.ERROR,
                "finding.sbomCreatorMissing",
                "$.metadata.manufacturer",
            )
        )

    if not isinstance(metadata.get("component"), dict):
        findings.append(
            _finding(
                "SG006",
                FindingLevel.ERROR,
                "finding.rootComponentMissing",
                "$.metadata.component",
            )
        )

    vulnerabilities = document.get("vulnerabilities")
    if isinstance(vulnerabilities, list) and vulnerabilities:
        findings.append(
            _finding(
                "SG007",
                FindingLevel.ERROR,
                "finding.embeddedVulnerabilities",
                "$.vulnerabilities",
            )
        )

    duplicate_refs = {
        reference
        for reference, count in Counter(
            component.bom_ref for component in components if component.bom_ref
        ).items()
        if count > 1
    }
    dependency_refs = _dependency_graph_refs(document)

    for path, component in raw_components_with_paths(document):
        _validate_component(
            component=component,
            path=path,
            duplicate_refs=duplicate_refs,
            dependency_refs=dependency_refs,
            document=document,
            findings=findings,
        )

    return findings


def compliance_score(findings: list[ValidationFinding]) -> int:
    penalty = {
        FindingLevel.ERROR: 12,
        FindingLevel.WARNING: 4,
        FindingLevel.INFO: 1,
    }
    return max(0, 100 - sum(penalty[finding.level] for finding in findings))


def _validate_component(
    *,
    component: dict[str, Any],
    path: str,
    duplicate_refs: set[str],
    dependency_refs: set[str],
    document: dict[str, Any],
    findings: list[ValidationFinding],
) -> None:
    name = _text(component.get("name")) or "(unnamed component)"
    params = {"component": name}
    bom_ref = _text(component.get("bom-ref"))

    if not bom_ref:
        findings.append(
            _finding(
                "SG101",
                FindingLevel.WARNING,
                "finding.componentRefMissing",
                f"{path}.bom-ref",
                params,
            )
        )
    else:
        if bom_ref in duplicate_refs:
            findings.append(
                _finding(
                    "SG102",
                    FindingLevel.ERROR,
                    "finding.componentRefDuplicate",
                    f"{path}.bom-ref",
                    {**params, "reference": bom_ref},
                )
            )
        if bom_ref not in dependency_refs:
            findings.append(
                _finding(
                    "SG106",
                    FindingLevel.ERROR,
                    "finding.dependencyNodeMissing",
                    "$.dependencies",
                    params,
                )
            )
        if not _has_completeness(document, bom_ref):
            findings.append(
                _finding(
                    "SG107",
                    FindingLevel.WARNING,
                    "finding.completenessMissing",
                    "$.compositions",
                    params,
                )
            )

    if not _text(component.get("name")):
        findings.append(
            _finding("SG103", FindingLevel.ERROR, "finding.componentNameMissing", f"{path}.name")
        )
    if not _text(component.get("version")):
        findings.append(
            _finding(
                "SG104",
                FindingLevel.ERROR,
                "finding.componentVersionMissing",
                f"{path}.version",
                params,
            )
        )
    if not _has_creator(component):
        findings.append(
            _finding(
                "SG105",
                FindingLevel.ERROR,
                "finding.componentCreatorMissing",
                f"{path}.manufacturer",
                params,
            )
        )
    if not _has_concluded_license(component):
        findings.append(
            _finding(
                "SG108",
                FindingLevel.ERROR,
                "finding.distributionLicenseMissing",
                f"{path}.licenses",
                params,
            )
        )

    filename = _property(component, "bsi:component:filename")
    if not filename:
        findings.append(
            _finding(
                "SG109",
                FindingLevel.WARNING,
                "finding.filenameMissing",
                f"{path}.properties",
                params,
            )
        )
    elif "/" in filename or "\\" in filename:
        findings.append(
            _finding(
                "SG110",
                FindingLevel.ERROR,
                "finding.filenamePath",
                f"{path}.properties",
                params,
            )
        )

    if not _has_sha512_distribution_hash(component):
        findings.append(
            _finding(
                "SG111",
                FindingLevel.WARNING,
                "finding.sha512Missing",
                f"{path}.externalReferences",
                params,
            )
        )

    for missing_code, invalid_code, property_name, message_key, missing_key in (
        (
            "SG112",
            "SG113",
            "bsi:component:executable",
            "finding.executableInvalid",
            "finding.executableMissing",
        ),
        (
            "SG114",
            "SG115",
            "bsi:component:archive",
            "finding.archiveInvalid",
            "finding.archiveMissing",
        ),
        (
            "SG116",
            "SG117",
            "bsi:component:structured",
            "finding.structuredInvalid",
            "finding.structuredMissing",
        ),
    ):
        value = _property(component, property_name)
        if not value:
            findings.append(
                _finding(
                    missing_code,
                    FindingLevel.WARNING,
                    missing_key,
                    f"{path}.properties",
                    params,
                )
            )
        elif value not in BSI_PROPERTY_VALUES[property_name]:
            findings.append(
                _finding(
                    invalid_code,
                    FindingLevel.ERROR,
                    message_key,
                    f"{path}.properties",
                    {**params, "value": value},
                )
            )


def _has_creator(owner: dict[str, Any]) -> bool:
    manufacturers = owner.get("manufacturer")
    if isinstance(manufacturers, dict):
        manufacturers = [manufacturers]
    if not isinstance(manufacturers, list):
        return False
    for manufacturer in manufacturers:
        if not isinstance(manufacturer, dict):
            continue
        urls = manufacturer.get("url")
        if isinstance(urls, str) and urls.strip():
            return True
        if isinstance(urls, list) and any(_text(url) for url in urls):
            return True
        contacts = manufacturer.get("contact")
        if isinstance(contacts, list) and any(
            isinstance(contact, dict) and _text(contact.get("email")) for contact in contacts
        ):
            return True
    return False


def _has_concluded_license(component: dict[str, Any]) -> bool:
    licenses = component.get("licenses")
    return isinstance(licenses, list) and any(
        isinstance(item, dict)
        and _text(item.get("expression"))
        and item.get("acknowledgement") == "concluded"
        for item in licenses
    )


def _has_sha512_distribution_hash(component: dict[str, Any]) -> bool:
    references = component.get("externalReferences")
    if not isinstance(references, list):
        return False
    for reference in references:
        if not isinstance(reference, dict) or reference.get("type") != "distribution":
            continue
        hashes = reference.get("hashes")
        if isinstance(hashes, list) and any(
            isinstance(item, dict)
            and str(item.get("alg", "")).upper() == "SHA-512"
            and _text(item.get("content"))
            for item in hashes
        ):
            return True
    return False


def _dependency_graph_refs(document: dict[str, Any]) -> set[str]:
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, list):
        return set()
    return {
        reference
        for item in dependencies
        if isinstance(item, dict) and (reference := _text(item.get("ref")))
    }


def _has_completeness(document: dict[str, Any], bom_ref: str) -> bool:
    compositions = document.get("compositions")
    if not isinstance(compositions, list):
        return False
    for composition in compositions:
        if not isinstance(composition, dict):
            continue
        if composition.get("aggregate") not in {"complete", "incomplete", "unknown"}:
            continue
        refs = composition.get("assemblies", []) + composition.get("dependencies", [])
        if bom_ref in refs:
            return True
    return False


def _property(component: dict[str, Any], name: str) -> str | None:
    properties = component.get("properties")
    if not isinstance(properties, list):
        return None
    for item in properties:
        if isinstance(item, dict) and item.get("name") == name:
            return _text(item.get("value"))
    return None


def _text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _finding(
    code: str,
    level: FindingLevel,
    message_key: str,
    path: str,
    params: dict[str, Any] | None = None,
) -> ValidationFinding:
    return ValidationFinding(
        code=code,
        level=level,
        message_key=message_key,
        path=path,
        params=params or {},
    )
