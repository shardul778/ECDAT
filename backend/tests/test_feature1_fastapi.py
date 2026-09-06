import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "ECDAT" in data["service"]
    assert data["version"] == "1.0.0"

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_cors_headers():
    response = client.options(
        "/",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET"
        }
    )
    # CORS middleware should respond with allow-origin
    assert response.headers.get("access-control-allow-origin") in ["http://localhost:5173", "*"]

def test_snippet_endpoint_success():
    response = client.get("/snippet?file=auth/login.py&line=10")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["line"] == 10
    assert len(data["lines"]) > 0
    target = next((l for l in data["lines"] if l["is_target"]), None)
    assert target is not None
    assert "hashlib.md5" in target["content"]

def test_snippet_endpoint_unavailable():
    response = client.get("/snippet?file=deleted_repo/does_not_exist.py&line=10")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "unavailable"
    assert "unavailable" in data["message"].lower()
