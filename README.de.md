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

## Integrität der Analyse

- CycloneDX-1.6- und 1.7-Dokumente werden zur Laufzeit gegen die gebündelten offiziellen JSON-Schemata geprüft.
- Der Komponentenbaum wird iterativ mit konfigurierbaren Grenzen für Anzahl und Tiefe verarbeitet.
- Die OSV-Schwere basiert auf dem passenden `affected[].severity` oder auf CVSS v2/v3/v4; qualitative Metadaten dienen als Rückfalloption.
- Behobene Versionen stammen ausschließlich aus dem zum geprüften Paket passenden `affected`-Eintrag.
- Der Bericht weist prüfbare und tatsächlich geprüfte Komponenten sowie Limits, Kürzungen und unvollständige OSV-Daten ausdrücklich aus.

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

Die Betriebsgrenzen lassen sich über `SUPPLYGUARD_MAX_COMPONENT_COUNT`, `SUPPLYGUARD_MAX_COMPONENT_DEPTH`, `SUPPLYGUARD_MAX_SCANNED_COMPONENTS`, `SUPPLYGUARD_MAX_OSV_PAGES` und `SUPPLYGUARD_MAX_OSV_DETAILS` konfigurieren.

## Docker

```bash
docker compose up --build
```

Weboberfläche: `http://localhost:3000`, API: `http://localhost:8000`.

## Prüfungen

```bash
cd apps/api
uv run pytest --cov=app --cov-report=term-missing --cov-fail-under=85
uv run ruff check .
uv run ruff format --check .

cd ../web
npm run check
npm run build
```

Die API-Tests enthalten fest auf einen Commit gesetzte CycloneDX-1.6- und 1.7-Dateien aus dem offiziellen Testbestand von [`CycloneDX/sbom-utility`](https://github.com/CycloneDX/sbom-utility). Commit, Prüfsummen und Lizenz sind in [`apps/api/tests/fixtures/upstream/README.md`](apps/api/tests/fixtures/upstream/README.md) dokumentiert.

Weitere Dokumentation: [`docs/architecture.md`](docs/architecture.md) · [`docs/threat-model.md`](docs/threat-model.md)

Lizenz: MIT
