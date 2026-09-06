import os
import pytest
from backend.pipeline.orchestrator import run_ecdat_pipeline
from backend.pipeline.cbom import generate_cbom

SAMPLE_REPO = os.path.join(os.path.dirname(__file__), "..", "..", "sample_repo")

@pytest.fixture(scope="module")
def scan_results():
    findings = run_ecdat_pipeline(SAMPLE_REPO)
    return findings

def test_explainability_why_reasons_present(scan_results):
    """Flaw 1: Every finding must include an explainable exposure_reason."""
    assert len(scan_results) > 0
    for f in scan_results:
        assert "exposure_reason" in f
        assert len(f["exposure_reason"].strip()) > 0

def test_test_only_exposure_and_high_dual_engine_confidence(scan_results):
    """Test-only Exposure: test_login.py, test_auth.py, test_crypto.py show High (Dual-Engine) and Test-only."""
    test_login_md5 = next(f for f in scan_results if "tests/auth/test_login.py" in f["file"] and f["algorithm"] == "MD5")
    test_auth_md5 = next(f for f in scan_results if "tests/test_auth.py" in f["file"] and f["algorithm"] == "MD5")
    test_crypto_sha1 = next(f for f in scan_results if "tests/test_crypto.py" in f["file"] and f["algorithm"] == "SHA1")

    for item in [test_login_md5, test_auth_md5, test_crypto_sha1]:
        assert item["confidence"] == "High (Dual-Engine)"
        assert item["exposure"] == "Test-only"
        assert item["exposure_reason"] == "Found in test file — both engines agree, but downweighted due to test context"
        assert item["risk_score"] == "Low"

    # Test-only with Medium (Single-Engine) confidence (Hardcoded Key in test_login.py)
    test_login_key = next(f for f in scan_results if "tests/auth/test_login.py" in f["file"] and f["algorithm"] == "Hardcoded Key")
    assert test_login_key["confidence"] == "Medium (Single-Engine)"
    assert test_login_key["exposure"] == "Test-only"
    assert test_login_key["exposure_reason"] == "Found in test file by one engine only — downweighted due to test context and partial detection"
    assert test_login_key["risk_score"] == "Low"

def test_aliased_crypto_medium_single_engine_disagreement(scan_results):
    """Dual-Engine Disagreement: aliased_crypto.py shows Medium (Single-Engine) and Internal-only."""
    aliased_item = next(f for f in scan_results if "crypto/aliased_crypto.py" in f["file"])
    assert aliased_item["algorithm"] == "MD5"
    assert aliased_item["confidence"] == "Medium (Single-Engine)"
    assert aliased_item["exposure"] == "Internal-only"
    assert aliased_item["risk_score"] == "Low"
    assert "ast" in aliased_item["engines"]

def test_auth_folder_internal_helper_tagged_critical(scan_results):
    """Folder Tagging: auth/internal_logger.py is tagged Critical because it resides in auth/."""
    auth_logger = next(f for f in scan_results if "auth/internal_logger.py" in f["file"])
    assert auth_logger["algorithm"] == "MD5"
    assert auth_logger["exposure"] == "Critical"
    assert "auth" in auth_logger["exposure_reason"].lower()
    assert auth_logger["risk_score"] == "High"

def test_variable_name_and_print_statement_no_false_positives(scan_results):
    """False-Positive Resistance: variable named md5_backup_do_not_use and print statement with 'auth'."""
    var_findings = [f for f in scan_results if "misc/variable_names.py" in f["file"]]
    assert len(var_findings) == 0, f"Expected 0 findings in variable_names.py, got: {var_findings}"

def test_complex_stress_file_deep_nesting(scan_results):
    """Scale / Stress: complex/enterprise_service.py has nested classes, methods, and try/except."""
    complex_findings = [f for f in scan_results if "complex/enterprise_service.py" in f["file"]]
    assert len(complex_findings) >= 3
    algos = {f["algorithm"] for f in complex_findings}
    assert "MD5" in algos
    assert "DES" in algos
    assert "SHA1" in algos

def test_empty_and_broken_syntax_graceful_recovery(scan_results):
    """Resilience: Scanner must not crash on empty.py or broken_syntax.py."""
    empty_findings = [f for f in scan_results if "misc/empty.py" in f["file"]]
    broken_findings = [f for f in scan_results if "misc/broken_syntax.py" in f["file"]]
    assert len(empty_findings) == 0
    assert len(broken_findings) == 0

def test_indirect_route_exposure(scan_results):
    """Indirect Route Exposure: undecorated helper called by route handler."""
    route_findings = [f for f in scan_results if "api/routes.py" in f["file"]]
    assert len(route_findings) >= 1
    indirect_finding = route_findings[0]
    assert indirect_finding["algorithm"] == "DES"
    assert indirect_finding["exposure"] == "Externally Exposed"
    assert "submit_order" in indirect_finding["exposure_reason"]
    assert indirect_finding["risk_score"] == "High"

def test_cbom_export_structure(scan_results):
    """CBOM JSON export structure verification (CycloneDX 1.6)."""
    cbom = generate_cbom(scan_results)
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert cbom["serialNumber"].startswith("urn:uuid:")
    assert len(cbom["components"]) == len(scan_results)
    for comp in cbom["components"]:
        assert comp["type"] == "cryptographic-asset"
        assert "bom-ref" in comp
        assert "name" in comp
        assert "cryptoProperties" in comp
        assert "algorithmProperties" in comp["cryptoProperties"]
        prop_map = {p["name"]: p["value"] for p in comp.get("properties", [])}
        assert "ecdat:file" in prop_map
        assert "ecdat:exposureReason" in prop_map
        assert "ecdat:recommendation" in prop_map
