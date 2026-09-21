from fastapi.testclient import TestClient

from pratica_api_system.api import app


def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-request-id"]


def test_request_id_is_preserved_when_valid():
    with TestClient(app) as client:
        response = client.get("/health", headers={"X-Request-ID": "soc-case-001"})

    assert response.headers["x-request-id"] == "soc-case-001"


def test_invalid_request_id_is_replaced():
    with TestClient(app) as client:
        response = client.get("/health", headers={"X-Request-ID": "bad id with spaces"})

    assert response.headers["x-request-id"] != "bad id with spaces"


def test_provider_inventory_is_available():
    with TestClient(app) as client:
        response = client.get("/v1/providers")

    assert response.status_code == 200
    names = {item["name"] for item in response.json()}
    assert {"VirusTotal", "AbuseIPDB", "URLhaus", "GreyNoise", "AlienVault OTX"} <= names
    assert {"NVD", "FIRST EPSS"} <= names
