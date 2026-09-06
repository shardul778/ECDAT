import pytest
from backend.pipeline.matcher import match_confidence, is_test_context

def test_is_test_context():
    assert is_test_context("tests/test_crypto.py") is True
    assert is_test_context("src/auth_test.py") is True
    assert is_test_context("mock/client.py") is True
    assert is_test_context("auth/login.py") is False
    assert is_test_context("api/routes.py") is False

def test_confidence_both_agree_high():
    semgrep = [{"file": "auth/login.py", "line": 10, "algorithm": "MD5"}]
    ast_res = [{"file": "auth/login.py", "line": 10, "algorithm": "MD5"}]
    results = match_confidence(semgrep, ast_res)
    
    assert len(results) == 1
    assert results[0]["confidence"] == "High (Dual-Engine)"
    assert results[0]["engines"] == ["semgrep", "ast"]

def test_confidence_single_engine_medium():
    # Only semgrep
    semgrep = [{"file": "auth/login.py", "line": 12, "algorithm": "DES"}]
    ast_res = []
    results1 = match_confidence(semgrep, ast_res)
    assert len(results1) == 1
    assert results1[0]["confidence"] == "Medium (Single-Engine)"
    assert results1[0]["engines"] == ["semgrep"]

    # Only AST
    semgrep_empty = []
    ast_res2 = [{"file": "auth/login.py", "line": 15, "algorithm": "RC4"}]
    results2 = match_confidence(semgrep_empty, ast_res2)
    assert len(results2) == 1
    assert results2[0]["confidence"] == "Medium (Single-Engine)"
    assert results2[0]["engines"] == ["ast"]

def test_confidence_dual_engine_in_test_file():
    # Dual-engine agreement in test file gives High (Dual-Engine) confidence
    semgrep = [{"file": "tests/test_crypto.py", "line": 5, "algorithm": "SHA1"}]
    ast_res = [{"file": "tests/test_crypto.py", "line": 5, "algorithm": "SHA1"}]
    results = match_confidence(semgrep, ast_res)
    
    assert len(results) == 1
    assert results[0]["confidence"] == "High (Dual-Engine)"
    assert results[0]["is_test_context"] is True

def test_confidence_line_proximity():
    # Semgrep reports line 20, AST reports line 21 (multi-line call)
    semgrep = [{"file": "crypto/keys.py", "line": 20, "algorithm": "Weak RSA (<2048)"}]
    ast_res = [{"file": "crypto/keys.py", "line": 21, "algorithm": "Weak RSA (<2048)"}]
    results = match_confidence(semgrep, ast_res)
    
    assert len(results) == 1
    assert results[0]["confidence"] == "High (Dual-Engine)"
