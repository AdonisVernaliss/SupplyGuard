# SupplyGuard

[English](README.md) · [Русский](README.ru.md)

SupplyGuard ist ein eigenständig entwickelter Arbeitsbereich für SBOM-Sicherheit. Die Anwendung validiert CycloneDX-JSON anhand der Feldzuordnung von **BSI TR-03183-2 v2.1.0**, fragt bekannte Schwachstellen bei [OSV](https://osv.dev/) ab und erstellt daraus einen übersichtlichen Bericht.

> SupplyGuard führt profilbezogene technische Prüfungen durch. Es ist kein offizielles BSI-Zertifizierungswerkzeug.

## Unterstütztes Profil

| Element | Unterstützter Wert |
| --- | --- |
| Profil | `BSI TR-03183-2` |
| Profilversion | `2.1.0` |
| Zuordnungsbasis | `CycloneDX JSON 1.6` |
| Akzeptierte CycloneDX-Versionen | `1.6`, `1.7` |
| Schwachstellenquelle | OSV-Live-API oder deterministische Offline-Demo |

Das Profil ist in [`apps/api/app/profile.py`](apps/api/app/profile.py) deklariert und Bestandteil des Health-Endpunkts, jeder Analyse und der lokalisierten Berichte. Details und Grenzen stehen in [`docs/bsi-profile.md`](docs/bsi-profile.md).

## Lokal starten

Voraussetzungen: Python 3.12+, [uv](https://docs.astral.sh/uv/), Node.js 22+.

```bash
# Terminal 1 — API
cd apps/api
uv sync --dev
uv run uvicorn app.main:app --reload

# Terminal 2 — Weboberfläche
cd apps/web
npm ci
npm run dev
```

Öffnen Sie `http://localhost:5173`. Die API-Dokumentation liegt unter `http://localhost:8000/docs`.

## Docker

```bash
docker compose up --build
```

Weboberfläche: `http://localhost:3000`, API: `http://localhost:8000`.

## Prüfungen

```bash
cd apps/api
uv run pytest
uv run ruff check .
uv run ruff format --check .

cd ../web
npm run check
npm run build
```

Weitere Dokumentation: [`docs/architecture.md`](docs/architecture.md) · [`docs/threat-model.md`](docs/threat-model.md)

Lizenz: MIT
