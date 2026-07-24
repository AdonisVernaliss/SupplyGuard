# SupplyGuard API

FastAPI service for CycloneDX JSON parsing, **BSI TR-03183-2 v2.1.0** profile checks, OSV vulnerability lookup, report persistence, and EN/DE/RU JSON export.

```bash
uv sync --dev
uv run uvicorn app.main:app --reload
```

OpenAPI: `http://localhost:8000/docs` · Health/profile: `http://localhost:8000/api/v1/health`

The profile identifier and supported mapping live in `app/profile.py`. Profile changes must be accompanied by validator, fixture, test, and documentation updates.
