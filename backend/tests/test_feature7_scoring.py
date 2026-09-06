import pytest
from backend.pipeline.scoring import (
    calculate_risk,
    get_recommendation,
    get_time_horizon,
    calculate_numeric_risk_score,
)

def test_calculate_risk_high_algorithms():
    assert calculate_risk("MD5", "Critical", is_test_context=False) == "High"
    assert calculate_risk("MD5", "Externally Exposed", is_test_context=False) == "High"
    assert calculate_risk("DES", "Externally Exposed", is_test_context=False) == "High"
    assert calculate_risk("DES", "Internal-only", is_test_context=False) == "High"
    assert calculate_risk("RC4", "Critical", is_test_context=False) == "High"
    assert calculate_risk("RC4", "Internal-only", is_test_context=False) == "High"
    assert calculate_risk("Hardcoded Key", "Critical", is_test_context=False) == "High"
    assert calculate_risk("Weak RSA (<2048)", "Internal-only", is_test_context=False) == "High"

def test_calculate_risk_internal_hashing():
    # Internal non-exposed MD5/SHA1 resolves to Low risk
    assert calculate_risk("MD5", "Internal-only", is_test_context=False) == "Low"
    assert calculate_risk("SHA1", "Internal-only", is_test_context=False) == "Low"
    assert calculate_risk("SHA1", "Critical", is_test_context=False) == "High"

def test_calculate_risk_rsa_quantum_tier():
    assert calculate_risk("RSA (>=2048)", "Internal-only", is_test_context=False) == "Medium"
    assert calculate_risk("RSA (>=2048)", "Critical", is_test_context=False) == "Medium"

def test_calculate_risk_test_context():
    # In test files, risk score is always Low
    assert calculate_risk("MD5", "Critical", is_test_context=True) == "Low"
    assert calculate_risk("DES", "Externally Exposed", is_test_context=True) == "Low"

def test_recommendations_exist():
    assert "SHA-256" in get_recommendation("MD5")
    assert "AES-256-GCM" in get_recommendation("DES")
    assert "AES-256-GCM" in get_recommendation("RC4")
    assert "Vault" in get_recommendation("Hardcoded Key")
    assert "2048" in get_recommendation("Weak RSA (<2048)")
    assert "Post-Quantum" in get_recommendation("RSA (>=2048)")

def test_time_horizon_immediate():
    # Classically broken / weak crypto must return Immediate
    assert get_time_horizon("MD5") == "Immediate (0-3 months)"
    assert get_time_horizon("DES") == "Immediate (0-3 months)"
    assert get_time_horizon("RC4") == "Immediate (0-3 months)"
    assert get_time_horizon("SHA1") == "Immediate (0-3 months)"
    assert get_time_horizon("SHA-1") == "Immediate (0-3 months)"
    assert get_time_horizon("Hardcoded Key") == "Immediate (0-3 months)"
    assert get_time_horizon("Weak RSA (<2048)") == "Immediate (0-3 months)"
    assert get_time_horizon("weak") == "Immediate (0-3 months)"

def test_time_horizon_pqc_migration():
    # Quantum-vulnerable public key crypto must return Medium-term PQC migration
    assert get_time_horizon("RSA (>=2048)") == "Medium-term (1-5 years) - PQC migration"
    assert get_time_horizon("RSA") == "Medium-term (1-5 years) - PQC migration"
    assert get_time_horizon("ECC") == "Medium-term (1-5 years) - PQC migration"
    assert get_time_horizon("ECDSA") == "Medium-term (1-5 years) - PQC migration"
    assert get_time_horizon("ECDH") == "Medium-term (1-5 years) - PQC migration"
    assert get_time_horizon("Diffie-Hellman") == "Medium-term (1-5 years) - PQC migration"
    assert get_time_horizon("quantum_vulnerable") == "Medium-term (1-5 years) - PQC migration"

def test_time_horizon_monitor():
    # Modern safe algorithms must return Monitor
    assert get_time_horizon("AES-256-GCM") == "Monitor - no action required"
    assert get_time_horizon("SHA-256") == "Monitor - no action required"
    assert get_time_horizon("SHA-512") == "Monitor - no action required"
    assert get_time_horizon("ChaCha20-Poly1305") == "Monitor - no action required"
    assert get_time_horizon("strong") == "Monitor - no action required"

def test_numeric_risk_scoring():
    # Range and sensitivity verification
    score_crit = calculate_numeric_risk_score("MD5", "Critical", confidence="High (Dual-Engine)")
    assert 50.0 <= score_crit <= 100.0
    
    score_single = calculate_numeric_risk_score("MD5", "Critical", confidence="Medium (Single-Engine)")
    assert score_single < score_crit  # Confidence downweighting works
    
    score_test = calculate_numeric_risk_score("MD5", "Test-only", is_test_context=True)
    assert score_test < score_crit
    assert score_test >= 0.0

