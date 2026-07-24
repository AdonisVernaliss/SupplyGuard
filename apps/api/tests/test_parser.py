import pytest

from app.parser import BomParseError, extract_components, parse_json_bom


def test_parse_rejects_non_object_json() -> None:
    with pytest.raises(BomParseError, match="root"):
        parse_json_bom(b"[]")


def test_extracts_primary_nested_components_and_relationships() -> None:
    document = {
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": "root",
                "name": "app",
                "version": "1",
            }
        },
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:npm/a@1",
                "name": "a",
                "version": "1",
                "purl": "pkg:npm/a@1",
                "components": [
                    {
                        "type": "library",
                        "bom-ref": "pkg:npm/b@2",
                        "name": "b",
                        "version": "2",
                        "purl": "pkg:npm/b@2",
                    }
                ],
            }
        ],
        "dependencies": [{"ref": "root", "dependsOn": ["pkg:npm/a@1"]}],
    }

    components = extract_components(document)

    assert [component.name for component in components] == ["app", "a", "b"]
    assert components[0].relationship == "root"
    assert components[1].relationship == "direct"
    assert components[2].relationship == "transitive"


def test_deeply_nested_components_are_rejected_without_recursion() -> None:
    document: dict = {"components": []}
    nested = document["components"]
    for index in range(12):
        component = {"name": f"component-{index}", "components": []}
        nested.append(component)
        nested = component["components"]

    with pytest.raises(BomParseError, match="nesting limit"):
        extract_components(document, max_component_depth=10)


def test_component_count_limit_is_enforced() -> None:
    document = {"components": [{"name": "a"}, {"name": "b"}, {"name": "c"}]}

    with pytest.raises(BomParseError, match="component limit"):
        extract_components(document, max_component_count=2)
