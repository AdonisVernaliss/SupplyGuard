import json
from collections.abc import Iterable
from typing import Any

from app.models import Component, DocumentMetadata


class BomParseError(ValueError):
    """Raised when an uploaded document cannot be parsed as a CycloneDX JSON BOM."""


def parse_json_bom(payload: bytes) -> dict[str, Any]:
    try:
        decoded = payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise BomParseError("The SBOM must be UTF-8 encoded.") from exc

    try:
        document = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise BomParseError(f"Invalid JSON at line {exc.lineno}, column {exc.colno}.") from exc

    if not isinstance(document, dict):
        raise BomParseError("The SBOM root must be a JSON object.")
    return document


def extract_document_metadata(document: dict[str, Any], filename: str) -> DocumentMetadata:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    root = metadata.get("component") if isinstance(metadata.get("component"), dict) else {}
    return DocumentMetadata(
        filename=filename,
        bom_format=_string_or_none(document.get("bomFormat")),
        spec_version=_string_or_none(document.get("specVersion")),
        serial_number=_string_or_none(document.get("serialNumber")),
        timestamp=_string_or_none(metadata.get("timestamp")),
        root_component=_component_display_name(root),
    )


def extract_components(document: dict[str, Any]) -> list[Component]:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    primary = metadata.get("component") if isinstance(metadata.get("component"), dict) else None
    top_level = document.get("components")
    component_items: list[dict[str, Any]] = []
    if primary:
        component_items.append(primary)
    if isinstance(top_level, list):
        component_items.extend(_walk_components(top_level))

    direct_refs = _direct_dependency_refs(document)
    components: list[Component] = []
    for index, raw_component in enumerate(component_items):
        bom_ref = _string_or_none(raw_component.get("bom-ref"))
        if index == 0 and primary is raw_component:
            relationship = "root"
        elif direct_refs is None:
            relationship = "unknown"
        elif bom_ref in direct_refs:
            relationship = "direct"
        else:
            relationship = "transitive"

        components.append(
            Component(
                bom_ref=bom_ref,
                name=_string_or_none(raw_component.get("name")) or "(unnamed component)",
                version=_string_or_none(raw_component.get("version")),
                component_type=_string_or_none(raw_component.get("type")) or "library",
                group=_string_or_none(raw_component.get("group")),
                purl=_string_or_none(raw_component.get("purl")),
                creator=_creator(raw_component),
                filename=_property(raw_component, "bsi:component:filename"),
                licenses=_licenses(raw_component),
                hashes=_distribution_hash_algorithms(raw_component),
                executable=_property(raw_component, "bsi:component:executable"),
                archive=_property(raw_component, "bsi:component:archive"),
                structured=_property(raw_component, "bsi:component:structured"),
                relationship=relationship,
            )
        )
    return components


def raw_components_with_paths(
    document: dict[str, Any],
) -> list[tuple[str, dict[str, Any]]]:
    result: list[tuple[str, dict[str, Any]]] = []
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    primary = metadata.get("component")
    if isinstance(primary, dict):
        result.append(("$.metadata.component", primary))
    top_level = document.get("components")
    if isinstance(top_level, list):
        result.extend(_walk_components_with_paths(top_level, "$.components"))
    return result


def _walk_components(items: Iterable[Any]) -> Iterable[dict[str, Any]]:
    for item in items:
        if not isinstance(item, dict):
            continue
        yield item
        nested = item.get("components")
        if isinstance(nested, list):
            yield from _walk_components(nested)


def _walk_components_with_paths(
    items: list[Any], base_path: str
) -> Iterable[tuple[str, dict[str, Any]]]:
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        path = f"{base_path}[{index}]"
        yield path, item
        nested = item.get("components")
        if isinstance(nested, list):
            yield from _walk_components_with_paths(nested, f"{path}.components")


def _direct_dependency_refs(document: dict[str, Any]) -> set[str] | None:
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    root = metadata.get("component") if isinstance(metadata.get("component"), dict) else {}
    root_ref = _string_or_none(root.get("bom-ref"))
    dependencies = document.get("dependencies")
    if not root_ref or not isinstance(dependencies, list):
        return None

    for dependency in dependencies:
        if not isinstance(dependency, dict) or dependency.get("ref") != root_ref:
            continue
        depends_on = dependency.get("dependsOn")
        if isinstance(depends_on, list):
            return {str(item) for item in depends_on}
    return None


def _creator(component: dict[str, Any]) -> str | None:
    manufacturers = component.get("manufacturer")
    if isinstance(manufacturers, dict):
        manufacturers = [manufacturers]
    if not isinstance(manufacturers, list):
        return None
    for manufacturer in manufacturers:
        if not isinstance(manufacturer, dict):
            continue
        contacts = manufacturer.get("contact")
        if isinstance(contacts, list):
            for contact in contacts:
                if isinstance(contact, dict):
                    email = _string_or_none(contact.get("email"))
                    if email:
                        return email
        urls = manufacturer.get("url")
        if isinstance(urls, str):
            return _string_or_none(urls)
        if isinstance(urls, list):
            for url in urls:
                value = _string_or_none(url)
                if value:
                    return value
    return None


def _licenses(component: dict[str, Any]) -> list[str]:
    raw_licenses = component.get("licenses")
    if not isinstance(raw_licenses, list):
        return []

    result: list[str] = []
    for entry in raw_licenses:
        if not isinstance(entry, dict):
            continue
        expression = _string_or_none(entry.get("expression"))
        if expression:
            result.append(expression)
            continue
        license_data = entry.get("license")
        if isinstance(license_data, dict):
            label = _string_or_none(license_data.get("id")) or _string_or_none(
                license_data.get("name")
            )
            if label:
                result.append(label)
    return result


def _distribution_hash_algorithms(component: dict[str, Any]) -> list[str]:
    result: list[str] = []
    references = component.get("externalReferences")
    if not isinstance(references, list):
        return result
    for reference in references:
        if not isinstance(reference, dict) or reference.get("type") != "distribution":
            continue
        hashes = reference.get("hashes")
        if not isinstance(hashes, list):
            continue
        result.extend(
            str(item["alg"])
            for item in hashes
            if isinstance(item, dict) and isinstance(item.get("alg"), str)
        )
    return result


def _property(component: dict[str, Any], name: str) -> str | None:
    properties = component.get("properties")
    if not isinstance(properties, list):
        return None
    for item in properties:
        if isinstance(item, dict) and item.get("name") == name:
            return _string_or_none(item.get("value"))
    return None


def _component_display_name(component: dict[str, Any]) -> str | None:
    name = _string_or_none(component.get("name"))
    version = _string_or_none(component.get("version"))
    if name and version:
        return f"{name} {version}"
    return name


def _string_or_none(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
