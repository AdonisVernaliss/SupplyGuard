import json
from typing import Any

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonValidator

from app.models import FindingLevel, ValidationFinding

SUPPORTED_SCHEMA_VERSIONS = {
    "1.6": SchemaVersion.V1_6,
    "1.7": SchemaVersion.V1_7,
}
MAX_SCHEMA_FINDINGS = 20


def validate_cyclonedx_schema(document: dict[str, Any]) -> list[ValidationFinding]:
    schema_version = SUPPORTED_SCHEMA_VERSIONS.get(document.get("specVersion"))
    if document.get("bomFormat") != "CycloneDX" or schema_version is None:
        return []

    validator = JsonValidator(schema_version)
    errors = validator.validate_str(json.dumps(document), all_errors=True)
    if errors is None:
        return []

    findings: list[ValidationFinding] = []
    for error in list(errors)[:MAX_SCHEMA_FINDINGS]:
        findings.append(
            ValidationFinding(
                code="SG008",
                level=FindingLevel.ERROR,
                message_key="finding.schemaValidation",
                path=_error_path(error),
                params={
                    "version": document["specVersion"],
                    "reason": _error_message(error),
                },
            )
        )
    return findings


def _error_path(error: Any) -> str:
    data = getattr(error, "data", None)
    path = getattr(data, "absolute_path", None)
    if path:
        return "$" + "".join(f"[{part}]" if isinstance(part, int) else f".{part}" for part in path)
    return "$"


def _error_message(error: Any) -> str:
    data = getattr(error, "data", None)
    message = getattr(data, "message", None) or str(error)
    return " ".join(str(message).split())[:300]
