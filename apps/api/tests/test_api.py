from fastapi.testclient import TestClient

from app.main import app


def test_health_exposes_supported_profile() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["version"] == "0.3.0"
    assert response.json()["supportedProfile"] == {
        "id": "BSI TR-03183-2",
        "version": "2.1.0",
        "format": "CycloneDX JSON",
        "mappingVersion": "1.6",
        "minimumSpecVersion": "1.6",
        "referenceUrl": (
            "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/"
            "TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf"
            "?__blob=publicationFile&v=5"
        ),
    }


def test_demo_analysis_and_russian_report() -> None:
    with TestClient(app) as client:
        response = client.post("/api/v1/analyses/demo")
        assert response.status_code == 201
        report = response.json()
        assert report["profile"]["version"] == "2.1.0"
        assert report["profile"]["mappingVersion"] == "1.6"
        assert report["summary"]["componentCount"] == 4
        assert report["summary"]["scannableComponentCount"] == 4
        assert report["summary"]["scannedComponentCount"] == 4
        assert report["summary"]["scanTruncated"] is False
        assert report["summary"]["vulnerabilityDataComplete"] is True
        assert report["summary"]["vulnerabilityCount"] == 2
        assert report["summary"]["complianceScore"] == 100
        assert report["provider"] == "demo-fixtures"

        localized = client.get(f"/api/v1/analyses/{report['id']}/report?lang=ru")
        assert localized.status_code == 200
        payload = localized.json()
        assert payload["language"] == "ru"
        assert payload["profile"]["version"] == "2.1.0"
        assert all("message" in finding for finding in payload["findings"])


def test_invalid_json_is_rejected() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyses?provider=demo",
            files={"file": ("broken.cdx.json", b"{", "application/json")},
        )
    assert response.status_code == 422
    assert "Invalid JSON" in response.json()["detail"]
