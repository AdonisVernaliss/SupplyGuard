# SupplyGuard API

FastAPI service for CycloneDX JSON parsing, **BSI TR-03183-2 v2.1.0** profile checks, OSV vulnerability lookup, report persistence, and EN/DE/RU JSON export.

The API performs local CycloneDX schema validation, bounded iterative component traversal, package-aware CVSS and fixed-version extraction, OSV pagination, and explicit scan-completeness reporting.

The package also installs a database-free CLI:

```bash
uv run supplyguard ../../samples/demo-shop.cdx.json --provider demo
uv run supplyguard application.cdx.json --format sarif --output supplyguard.sarif --fail-on high
```

See [`../../docs/cli.md`](../../docs/cli.md) for policy flags, exit codes, privacy behavior, and GitHub Code Scanning integration.

```bash
uv sync --dev
uv run uvicorn app.main:app --reload
```

Tests and the enforced coverage threshold:

```bash
uv run pytest --cov=app --cov-report=term-missing --cov-fail-under=85
```

OpenAPI: `http://localhost:8000/docs` · Health/profile: `http://localhost:8000/api/v1/health`

The profile identifier and supported mapping live in `app/profile.py`. Profile changes must be accompanied by validator, fixture, test, and documentation updates.
