import json
from pathlib import Path

import pytest

from app.cli import EXIT_OK, EXIT_OPERATIONAL_ERROR, EXIT_POLICY_FAILED, main
from app.service import demo_bom_bytes


@pytest.fixture
def demo_bom(tmp_path: Path) -> Path:
    path = tmp_path / "demo.cdx.json"
    path.write_bytes(demo_bom_bytes())
    return path


def test_cli_writes_localized_json_without_database(
    demo_bom: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main([str(demo_bom), "--provider", "demo", "--language", "de"])

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == EXIT_OK
    assert captured.err == ""
    assert report["language"] == "de"
    assert report["provider"] == "demo-fixtures"
    assert report["profile"]["version"] == "2.1.0"


def test_cli_writes_sarif_and_enforces_vulnerability_policy(
    demo_bom: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "supplyguard.sarif"
    exit_code = main(
        [
            str(demo_bom),
            "--provider",
            "demo",
            "--format",
            "sarif",
            "--output",
            str(output),
            "--fail-on",
            "high",
        ]
    )

    captured = capsys.readouterr()
    sarif = json.loads(output.read_text())
    assert exit_code == EXIT_POLICY_FAILED
    assert captured.out == ""
    assert "vulnerabilities at or above high" in captured.err
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["semanticVersion"] == "0.3.0"
    assert any(
        result["properties"]["category"] == "vulnerability"
        for result in sarif["runs"][0]["results"]
    )


def test_cli_can_fail_on_validation_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    invalid_profile = tmp_path / "invalid-profile.cdx.json"
    invalid_profile.write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1})
    )
    exit_code = main([str(invalid_profile), "--provider", "demo", "--fail-on-validation-errors"])

    captured = capsys.readouterr()
    assert exit_code == EXIT_POLICY_FAILED
    assert "validation errors" in captured.err


def test_cli_can_require_complete_results(
    demo_bom: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("SUPPLYGUARD_MAX_SCANNED_COMPONENTS", "1")

    exit_code = main([str(demo_bom), "--provider", "demo", "--require-complete"])

    captured = capsys.readouterr()
    assert exit_code == EXIT_POLICY_FAILED
    assert "analysis is incomplete" in captured.err


def test_cli_reports_invalid_input_as_operational_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("not-json")

    exit_code = main([str(invalid), "--provider", "demo"])

    captured = capsys.readouterr()
    assert exit_code == EXIT_OPERATIONAL_ERROR
    assert captured.out == ""
    assert "Invalid JSON" in captured.err


def test_cli_refuses_to_overwrite_input(demo_bom: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main([str(demo_bom), "--provider", "demo", "--output", str(demo_bom)])

    captured = capsys.readouterr()
    assert exit_code == EXIT_OPERATIONAL_ERROR
    assert "must not overwrite" in captured.err
