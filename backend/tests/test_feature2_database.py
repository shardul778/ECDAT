import os
import tempfile
import pytest
from backend.database import init_db, insert_finding, insert_findings_batch, get_all_findings, clear_findings

@pytest.fixture
def temp_db():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_findings.db")
    init_db(db_path)
    yield db_path
    if os.path.exists(db_path):
        os.remove(db_path)

def test_init_db_creates_table(temp_db):
    findings = get_all_findings(temp_db)
    assert findings == []

def test_insert_and_get_finding(temp_db):
    row_id = insert_finding(
        file="auth/login.py",
        line=15,
        algorithm="MD5",
        confidence="High",
        exposure="Critical",
        risk_score="High",
        exposure_reason="auth keyword",
        db_path=temp_db
    )
    assert row_id == 1

    findings = get_all_findings(temp_db)
    assert len(findings) == 1
    f = findings[0]
    assert f["file"] == "auth/login.py"
    assert f["line"] == 15
    assert f["algorithm"] == "MD5"
    assert f["confidence"] == "High"
    assert f["exposure"] == "Critical"
    assert f["risk_score"] == "High"
    assert f["exposure_reason"] == "auth keyword"
    assert "created_at" in f

def test_insert_findings_batch(temp_db):
    batch = [
        {
            "file": "api/routes.py",
            "line": 22,
            "algorithm": "DES",
            "confidence": "High",
            "exposure": "Externally Exposed",
            "exposure_reason": "route handler",
            "risk_score": "High"
        },
        {
            "file": "tests/test_crypto.py",
            "line": 8,
            "algorithm": "SHA1",
            "confidence": "Low",
            "exposure": "Internal-only",
            "exposure_reason": "test context",
            "risk_score": "Low"
        }
    ]
    insert_findings_batch(batch, temp_db)
    findings = get_all_findings(temp_db)
    assert len(findings) == 2
    assert findings[0]["algorithm"] == "DES"
    assert findings[1]["algorithm"] == "SHA1"

def test_clear_findings(temp_db):
    insert_finding("a.py", 1, "RC4", "High", "Internal-only", "High", "reason", temp_db)
    assert len(get_all_findings(temp_db)) == 1
    clear_findings(temp_db)
    assert len(get_all_findings(temp_db)) == 0
