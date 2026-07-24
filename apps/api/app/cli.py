import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from app.config import Settings
from app.localization import SUPPORTED_LANGUAGES, localized_report
from app.models import AnalysisReport, FindingLevel, Severity
from app.parser import BomParseError
from app.sarif import sarif_report
from app.service import analyze_bom
from app.version import APP_VERSION
from app.vulnerabilities import (
    DemoVulnerabilityProvider,
    OsvVulnerabilityProvider,
    VulnerabilityProvider,
    VulnerabilityProviderError,
)

EXIT_OK = 0
EXIT_POLICY_FAILED = 1
EXIT_OPERATIONAL_ERROR = 2
SEVERITY_RANK = {
    Severity.UNKNOWN: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    input_path = Path(args.sbom)

    try:
        payload = input_path.read_bytes()
        if not payload:
            raise BomParseError("The SBOM file is empty.")
        settings = Settings()
        if len(payload) > settings.max_upload_bytes:
            raise BomParseError(
                f"The SBOM exceeds the configured limit of {settings.max_upload_bytes} bytes."
            )
        report = asyncio.run(
            analyze_bom(
                payload=payload,
                filename=input_path.name,
                provider=_provider(args.provider, settings),
                max_scanned_components=settings.max_scanned_components,
                max_component_count=settings.max_component_count,
                max_component_depth=settings.max_component_depth,
            )
        )
        document = _output_document(report, args.format, args.language)
        _write_output(document, args.output, input_path)
    except (OSError, BomParseError, VulnerabilityProviderError) as exc:
        print(f"SupplyGuard: {exc}", file=sys.stderr)
        return EXIT_OPERATIONAL_ERROR

    failed_reasons = policy_failures(
        report,
        fail_on=args.fail_on,
        fail_on_validation_errors=args.fail_on_validation_errors,
        require_complete=args.require_complete,
    )
    if failed_reasons:
        print("SupplyGuard policy failed: " + "; ".join(failed_reasons), file=sys.stderr)
        return EXIT_POLICY_FAILED
    return EXIT_OK


def policy_failures(
    report: AnalysisReport,
    *,
    fail_on: str,
    fail_on_validation_errors: bool,
    require_complete: bool,
) -> list[str]:
    failures: list[str] = []
    if fail_on == "any" and report.vulnerabilities:
        failures.append(f"{len(report.vulnerabilities)} vulnerabilities found")
    elif fail_on != "none":
        threshold = SEVERITY_RANK[Severity(fail_on)]
        matched = [
            item for item in report.vulnerabilities if SEVERITY_RANK[item.severity] >= threshold
        ]
        if matched:
            failures.append(f"{len(matched)} vulnerabilities at or above {fail_on}")

    validation_errors = sum(1 for finding in report.findings if finding.level is FindingLevel.ERROR)
    if fail_on_validation_errors and validation_errors:
        failures.append(f"{validation_errors} validation errors")
    if require_complete and (
        report.summary.scan_truncated or not report.summary.vulnerability_data_complete
    ):
        failures.append("vulnerability analysis is incomplete")
    return failures


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="supplyguard",
        description=(
            "Validate a CycloneDX JSON SBOM and scan its packages for known vulnerabilities."
        ),
    )
    parser.add_argument("sbom", help="Path to a CycloneDX JSON SBOM")
    parser.add_argument(
        "--provider",
        choices=("osv", "demo"),
        default="osv",
        help="Vulnerability provider (default: osv)",
    )
    parser.add_argument(
        "--format",
        choices=("json", "sarif"),
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--output",
        default="-",
        help="Output file, or - for stdout (default: -)",
    )
    parser.add_argument(
        "--language",
        choices=tuple(sorted(SUPPORTED_LANGUAGES)),
        default="en",
        help="Language for validation messages (default: en)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("none", "critical", "high", "medium", "low", "any"),
        default="none",
        help="Return exit code 1 when the vulnerability threshold is met",
    )
    parser.add_argument(
        "--fail-on-validation-errors",
        action="store_true",
        help="Return exit code 1 when profile or schema validation has errors",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="Return exit code 1 when vulnerability results are partial or truncated",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {APP_VERSION}")
    return parser


def _provider(name: str, settings: Settings) -> VulnerabilityProvider:
    if name == "demo":
        return DemoVulnerabilityProvider()
    return OsvVulnerabilityProvider(
        base_url=settings.osv_base_url,
        timeout_seconds=settings.osv_timeout_seconds,
        max_pages=settings.max_osv_pages,
        max_details=settings.max_osv_details,
    )


def _output_document(report: AnalysisReport, output_format: str, language: str) -> dict[str, Any]:
    if output_format == "sarif":
        return sarif_report(report, language)
    return localized_report(report, language)


def _write_output(document: dict[str, Any], output: str, input_path: Path) -> None:
    serialized = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    if output == "-":
        sys.stdout.write(serialized)
        return

    output_path = Path(output)
    if output_path.resolve() == input_path.resolve():
        raise OSError("output path must not overwrite the input SBOM")
    output_path.write_text(serialized, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
