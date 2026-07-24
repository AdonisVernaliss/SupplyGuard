# Command-line interface

SupplyGuard `0.3.0` can run the same analysis pipeline as the API without starting a server or writing a report to the database.

## Install in the repository

```bash
cd apps/api
uv sync --frozen --dev
uv run supplyguard --version
```

## Scan an SBOM

Live OSV analysis with a JSON report on stdout:

```bash
uv run supplyguard ../../samples/demo-shop.cdx.json
```

Deterministic offline analysis:

```bash
uv run supplyguard ../../samples/demo-shop.cdx.json --provider demo --output report.json
```

Generate SARIF and enforce a CI policy:

```bash
uv run supplyguard application.cdx.json \
  --format sarif \
  --output supplyguard.sarif \
  --fail-on high \
  --fail-on-validation-errors \
  --require-complete
```

The JSON report can use `--language en`, `--language de`, or `--language ru`. SARIF uses the same language for profile finding messages.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Analysis completed and the selected policy passed |
| `1` | Analysis completed, the report was written, and the selected policy failed |
| `2` | Input, configuration, output, or vulnerability-provider failure |

`--fail-on` accepts `none`, `critical`, `high`, `medium`, `low`, or `any`. The threshold is inclusive. Unknown severity is included only by `any`.

`--require-complete` fails the policy if a component or OSV detail limit was reached, pagination was truncated, or an OSV detail request failed. This prevents a partial result from silently passing CI.

## GitHub Code Scanning

[`docs/examples/github-code-scanning.yml`](examples/github-code-scanning.yml) is a copy-ready workflow. Replace its `SBOM_PATH` with the repository's CycloneDX file. The scan step is allowed to finish long enough to produce SARIF, the SARIF is uploaded even when the policy fails, and the final step restores the failed workflow status.

The example pins all third-party Actions to commit SHAs. The CodeQL upload action version is recorded in the inline comment so dependency automation can update it.

## Privacy and limits

The CLI does not initialize the database and does not persist the normalized report unless `--output` names a file. Live OSV mode still sends package URLs to OSV. Use `--provider demo` when no network disclosure is acceptable.

Upload size, component traversal, scan, OSV page, and OSV detail limits use the same `SUPPLYGUARD_*` environment variables as the API.
