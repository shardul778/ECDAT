import os
import tempfile
import pytest
from backend.scanners.semgrep_scanner import run_semgrep_scan
from backend.scanners.ast_scanner import run_ast_scan, is_hardcoded_secret
from backend.pipeline.orchestrator import run_ecdat_pipeline

RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "rules", "crypto_rules.yaml")
SAMPLE_REPO = os.path.join(os.path.dirname(__file__), "..", "..", "sample_repo")

def test_case1_sample_repo_key_management_detected():
    """Case 1: Re-scan sample_repo — key_management.py's hardcoded key must be detected"""
    findings = run_ecdat_pipeline(SAMPLE_REPO)
    key_findings = [f for f in findings if "key_management.py" in f["file"] and f["algorithm"] == "Hardcoded Key"]
    assert len(key_findings) == 1
    f = key_findings[0]
    assert f["confidence"] == "High (Dual-Engine)"
    assert f["risk_score"] == "High"
    assert f["line"] == 27

def test_case2_short_value_and_bare_key_not_flagged():
    """Case 2: Short value like key = ' di' (3 chars) must NOT be flagged"""
    with tempfile.TemporaryDirectory() as td:
        file_path = os.path.join(td, "test_short_key.py")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write('key = " di"\n')
            f.write('secret = "short"\n')
            f.write('api_key = "abc123"\n')  # less than 12 chars

        semgrep_findings = run_semgrep_scan(td, RULES_PATH)
        ast_findings = run_ast_scan(td)
        pipeline_findings = run_ecdat_pipeline(td)

        assert len([f for f in semgrep_findings if f["algorithm"] == "Hardcoded Key"]) == 0
        assert len([f for f in ast_findings if f["algorithm"] == "Hardcoded Key"]) == 0
        assert len([f for f in pipeline_findings if f["algorithm"] == "Hardcoded Key"]) == 0

def test_case3_placeholder_value_not_flagged():
    """Case 3: secret_key = 'testing' and other placeholders must NOT be flagged"""
    with tempfile.TemporaryDirectory() as td:
        file_path = os.path.join(td, "test_placeholder.py")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write('secret_key = "testing"\n')
            f.write('api_key = "changeme"\n')
            f.write('password = "password"\n')
            f.write('token = "placeholder"\n')
            f.write('auth_token = "123456"\n')
            f.write('private_key = "example"\n')

        semgrep_findings = run_semgrep_scan(td, RULES_PATH)
        ast_findings = run_ast_scan(td)
        pipeline_findings = run_ecdat_pipeline(td)

        assert len([f for f in semgrep_findings if f["algorithm"] == "Hardcoded Key"]) == 0
        assert len([f for f in ast_findings if f["algorithm"] == "Hardcoded Key"]) == 0
        assert len([f for f in pipeline_findings if f["algorithm"] == "Hardcoded Key"]) == 0

def test_case4_real_alphanumeric_secret_flagged():
    """Case 4: Real-looking 20+ char mixed alphanumeric secret in api_key must be flagged"""
    with tempfile.TemporaryDirectory() as td:
        file_path = os.path.join(td, "test_valid_secret.py")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write('api_key = "sk_prod_9988aabbcc112233"\n')

        semgrep_findings = run_semgrep_scan(td, RULES_PATH)
        ast_findings = run_ast_scan(td)
        pipeline_findings = run_ecdat_pipeline(td)

        semgrep_keys = [f for f in semgrep_findings if f["algorithm"] == "Hardcoded Key"]
        ast_keys = [f for f in ast_findings if f["algorithm"] == "Hardcoded Key"]
        pipeline_keys = [f for f in pipeline_findings if f["algorithm"] == "Hardcoded Key"]

        assert len(semgrep_keys) == 1
        assert len(ast_keys) == 1
        assert len(pipeline_keys) == 1
        assert pipeline_keys[0]["confidence"] == "High (Dual-Engine)"

def test_ast_helper_unit_tests():
    """Unit tests for AST is_hardcoded_secret helper"""
    # Bare key / secret rejected
    assert not is_hardcoded_secret("key", " di")
    assert not is_hardcoded_secret("secret", "super_secret_master_12345")
    
    # Placeholders rejected
    assert not is_hardcoded_secret("secret_key", "testing")
    assert not is_hardcoded_secret("api_key", "CHANGEME")
    assert not is_hardcoded_secret("password", "123456")
    assert not is_hardcoded_secret("token", "")
    
    # Short length (< 12) rejected
    assert not is_hardcoded_secret("api_key", "short123")
    
    # Only letters or only digits rejected
    assert not is_hardcoded_secret("api_key", "purealphaonlysecretstring")
    assert not is_hardcoded_secret("api_key", "12345678901234567890")
    
    # Valid secrets accepted
    assert is_hardcoded_secret("api_key", "sk_prod_9988aabbcc112233")
    assert is_hardcoded_secret("secret_key", "my_secret_token_123456")
    assert is_hardcoded_secret("api_secret_key", "sk_live_enterprise_master_998877665544")
