import os
os.environ["DATABASE_URL"] = "sqlite:///./test_threatintel.db"
from fastapi.testclient import TestClient
from main import app

def test_health_and_dashboard_contract():
    with TestClient(app) as client:
        assert client.get("/health").json()["status"] == "ok"
        assert client.get("/api/v1/iocs").json()["total"] >= 1
        assert client.get("/api/v1/analytics/summary").status_code == 200

def test_stix_and_deduplication():
    with TestClient(app) as client:
        payload = {"value":"training.example","type":"domain-name","confidence":90,"source":"Test"}
        first = client.post("/api/v1/iocs", json=payload)
        second = client.post("/api/v1/iocs", json=payload)
        assert first.status_code == 201 and second.json()["created"] is False
        assert client.get(f"/api/v1/iocs/{first.json()['id']}/stix").json()["spec_version"] == "2.1"
