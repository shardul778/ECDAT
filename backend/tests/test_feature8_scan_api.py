import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import init_db

@pytest.fixture(autouse=True)
def setup_test_db(monkeypatch):
    temp_dir = tempfile.mkdtemp()
    temp_db_path = os.path.join(temp_dir, "test_api_findings.db")
    monkeypatch.setenv("ECDAT_DB_PATH", temp_db_path)
    init_db(temp_db_path)
    yield temp_db_path
    if os.path.exists(temp_db_path):
        os.remove(temp_db_path)

client = TestClient(app)

def test_full_scan_api_flow():
    # 1. Trigger scan
    response = client.post("/scan")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["total_findings"] >= 5
    
    findings = data["findings"]
    algos = {f["algorithm"] for f in findings}
    assert "MD5" in algos
    assert "DES" in algos
    assert "Hardcoded Key" in algos
    assert "Weak RSA (<2048)" in algos
    assert "SHA1" in algos

    # Check exposure & reason for auth MD5
    auth_findings = [f for f in findings if "auth/login.py" in f["file"]]
    assert len(auth_findings) > 0
    assert auth_findings[0]["exposure"] == "Critical"
    assert "auth" in auth_findings[0]["exposure_reason"].lower()
    assert auth_findings[0]["risk_score"] == "High"

    # Check exposure for route DES (direct or indirect)
    api_findings = [f for f in findings if "api/routes.py" in f["file"]]
    assert len(api_findings) > 0
    assert api_findings[0]["exposure"] == "Externally Exposed"
    assert "route" in api_findings[0]["exposure_reason"].lower()
    assert api_findings[0]["risk_score"] == "High"

    # Check test file confidence & risk
    test_findings = [f for f in findings if "test_crypto.py" in f["file"]]
    assert len(test_findings) > 0
    assert test_findings[0]["confidence"] == "High (Dual-Engine)"
    assert test_findings[0]["exposure"] == "Test-only"
    assert test_findings[0]["risk_score"] == "Low"
    assert "test" in test_findings[0]["exposure_reason"].lower()

def test_get_findings_endpoint():
    client.post("/scan")
    response = client.get("/findings")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert len(data["findings"]) >= 5
    for f in data["findings"]:
        assert "exposure_reason" in f

def test_export_cbom_endpoint():
    client.post("/scan")
    response = client.get("/export/cbom")
    assert response.status_code == 200
    cbom = response.json()
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert cbom["serialNumber"].startswith("urn:uuid:")
    assert "components" in cbom
    assert len(cbom["components"]) >= 5
    for comp in cbom["components"]:
        assert comp["type"] == "cryptographic-asset"
        assert "bom-ref" in comp
        assert "name" in comp
        assert "cryptoProperties" in comp
        assert "assetType" in comp["cryptoProperties"]
        assert "algorithmProperties" in comp["cryptoProperties"]
        assert "properties" in comp
        prop_map = {p["name"]: p["value"] for p in comp["properties"]}
        assert "ecdat:file" in prop_map
        assert "ecdat:line" in prop_map
        assert "ecdat:confidence" in prop_map
        assert "ecdat:exposure" in prop_map
        assert "ecdat:riskScore" in prop_map
        assert "ecdat:recommendation" in prop_map
        assert len(prop_map["ecdat:recommendation"]) > 0
