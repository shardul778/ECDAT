import os
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.pipeline.scoring import get_recommendation

client = TestClient(app)

def test_detail_view_critical_dual_engine_auth_login():
    """Test 1: High-risk, Dual-Engine, Critical exposure finding (auth/login.py MD5)."""
    # Verify snippet endpoint returns accurate snippet with target line highlighted
    res = client.get("/snippet?file=auth/login.py&line=10")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["file"] == "auth/login.py"
    assert data["line"] == 10
    assert len(data["lines"]) >= 3
    
    target_line = next(l for l in data["lines"] if l["is_target"])
    assert target_line["line_number"] == 10
    assert "hashlib.md5" in target_line["content"]
    
    # Recommendation check
    rec = get_recommendation("MD5")
    assert "SHA-256" in rec or "Argon2id" in rec

def test_detail_view_single_engine_aliased_crypto():
    """Test 2: Medium-risk / Low-risk Single-Engine finding (crypto/aliased_crypto.py)."""
    res = client.get("/snippet?file=crypto/aliased_crypto.py&line=13")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    target_line = next(l for l in data["lines"] if l["is_target"])
    assert target_line["line_number"] == 13
    assert "md5_func_alias" in target_line["content"]

def test_detail_view_test_only_exposure():
    """Test 3: Test-only exposure finding (tests/test_auth.py)."""
    res = client.get("/snippet?file=tests/test_auth.py&line=12")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    target_line = next(l for l in data["lines"] if l["is_target"])
    assert target_line["line_number"] == 12
    assert "hashlib.md5" in target_line["content"]

def test_detail_view_indirect_route_exposure_api_routes():
    """Test 4: Indirect route exposure finding (api/routes.py DES cipher helper)."""
    res = client.get("/snippet?file=api/routes.py&line=14")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    target_line = next(l for l in data["lines"] if l["is_target"])
    assert target_line["line_number"] == 14
    assert "DES.new" in target_line["content"]
    # Ensure line 14 is the helper call, not the route decorator
    assert "@app.post" not in target_line["content"]

def test_detail_view_snippet_unavailable_graceful_handling():
    """Test 6: Deleted/non-existent repo file returns graceful unavailable status."""
    res = client.get("/snippet?file=deleted_temp_repo/missing_auth.py&line=10")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "unavailable"
    assert "unavailable" in data["message"].lower()
    assert data["lines"] == []

def test_detail_view_snippet_out_of_bounds_line():
    """Test boundary: line number exceeds file line count."""
    res = client.get("/snippet?file=auth/login.py&line=9999")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "unavailable"
    assert data["lines"] == []
