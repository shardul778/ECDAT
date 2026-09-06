from typing import Dict, Any

def calculate_risk(algorithm: str, exposure: str, is_test_context: bool = False) -> str:
    """
    Computes a rule-based risk score: High / Medium / Low.
    
    Security Impact Rules:
    - Test-only / Test context -> Low risk (test suites do not run in production traffic)
    - Critical or Externally Exposed + (MD5, SHA1, DES, RC4, Hardcoded Key, Weak RSA) -> High risk
    - Broken ciphers (DES, RC4), hardcoded secrets, weak RSA (<2048) in production -> High risk
    - MD5 / SHA1 in purely Internal-only non-exposed helper -> Low risk
    - RSA (>=2048) -> Medium risk (Classically secure, Quantum Vulnerable tier)
    - Modern safe algorithms -> Low / Safe
    """
    algo_upper = algorithm.upper()
    
    # 1. Test-only exposure is always Low risk
    if exposure == "Test-only" or is_test_context:
        return "Low"

    # 2. Hardcoded secrets, broken symmetric ciphers (DES, RC4), and broken RSA keys (<2048)
    if any(k in algo_upper for k in ["DES", "RC4", "ARC4", "HARDCODED", "WEAK RSA"]):
        return "High"

    # 3. MD5 / SHA1 hash functions
    if "MD5" in algo_upper or "SHA1" in algo_upper or "SHA-1" in algo_upper:
        if exposure in ("Critical", "Externally Exposed"):
            return "High"
        # Purely internal-only utility hashing
        return "Low"

    # 4. Classically strong RSA (>=2048 bits) -> Quantum Vulnerable Tier
    if "RSA" in algo_upper:
        return "Medium"

    # 5. Modern safe algorithms
    return "Low"

def get_recommendation(algorithm: str) -> str:
    """Returns cryptographic remediation advice for CBOM export."""
    algo_upper = algorithm.upper()
    if "MD5" in algo_upper:
        return "Migrate to SHA-256 or SHA-3 for hashing; use Argon2id/bcrypt for password hashing."
    if "SHA1" in algo_upper or "SHA-1" in algo_upper:
        return "Migrate to SHA-256, SHA-384, or SHA-512."
    if "DES" in algo_upper:
        return "Replace DES with AES-256-GCM or ChaCha20-Poly1305."
    if "RC4" in algo_upper or "ARC4" in algo_upper:
        return "Replace RC4 stream cipher with AES-256-GCM or ChaCha20-Poly1305."
    if "HARDCODED" in algo_upper:
        return "Remove hardcoded secret; load securely from environment variables or a Secret Vault (e.g. AWS Secrets Manager, HashiCorp Vault)."
    if "WEAK RSA" in algo_upper:
        return "Upgrade RSA key length to at least 2048 (preferably 3072/4096) or transition to Post-Quantum Cryptography (ML-KEM/Kyber, ML-DSA/Dilithium)."
    if "RSA" in algo_upper:
        return "Classically secure, but prepare Post-Quantum Cryptography (PQC) migration strategy (NIST FIPS 203 / ML-KEM)."
    return "Adopt NIST-recommended post-quantum and modern cryptographic standards."

def get_time_horizon(algorithm_or_class: str) -> str:
    """
    Returns Mosca-style migration roadmap classification:
    - "Immediate (0-3 months)": Classically broken / weak cryptography (MD5, SHA1, DES, RC4, Hardcoded secrets, Weak RSA)
    - "Medium-term (1-5 years) - PQC migration": Quantum-vulnerable public key cryptography (RSA >=2048, ECC, ECDSA, DH, DSA)
    - "Monitor - no action required": Modern safe algorithms (AES-GCM, SHA-256, SHA-512, ChaCha20)
    """
    val = algorithm_or_class.strip().lower()
    
    # Check direct class matches
    if val in ("weak", "broken", "immediate"):
        return "Immediate (0-3 months)"
    if val in ("quantum_vulnerable", "quantum", "pqc", "medium_term", "medium-term"):
        return "Medium-term (1-5 years) - PQC migration"
    if val in ("strong", "safe", "modern", "monitor"):
        return "Monitor - no action required"

    algo_upper = algorithm_or_class.upper()
    
    # 1. Classically broken algorithms -> Immediate
    if any(k in algo_upper for k in ["MD5", "SHA1", "SHA-1", "DES", "RC4", "ARC4", "HARDCODED", "WEAK RSA", "VULNERABLE DEPENDENCY"]):
        return "Immediate (0-3 months)"
    
    # 2. Quantum-vulnerable public key crypto -> Medium-term PQC
    if any(k in algo_upper for k in ["RSA", "ECC", "ECDSA", "ECDH", "DSA", "DH", "DIFFIE-HELLMAN", "ED25519", "SECP"]):
        return "Medium-term (1-5 years) - PQC migration"
    
    # 3. Modern safe algorithms -> Monitor
    return "Monitor - no action required"

def calculate_numeric_risk_score(
    algorithm: str,
    exposure: str,
    confidence: str = "High (Dual-Engine)",
    is_test_context: bool = False
) -> float:
    """
    Computes a continuous 0-100 risk score based on:
    - Base Severity (0-50): Determined by cryptographic strength / brokenness
    - Exposure Weight (0-25): Critical (+25), Externally Exposed (+20), Internal (+5), Test (-25)
    - Confidence Multiplier: High / Dual-Engine (1.0), Medium / Single-Engine (0.7)
    """
    algo_upper = algorithm.upper()
    
    # Base severity (0 - 50)
    if any(k in algo_upper for k in ["HARDCODED", "DES", "RC4", "ARC4"]):
        base = 50.0
    elif "WEAK RSA" in algo_upper:
        base = 45.0
    elif any(k in algo_upper for k in ["MD5", "SHA1", "SHA-1", "VULNERABLE DEPENDENCY"]):
        base = 40.0
    elif any(k in algo_upper for k in ["RSA", "ECC", "ECDSA", "ECDH", "DSA", "DH"]):
        base = 25.0
    elif any(k in algo_upper for k in ["AES", "SHA-256", "SHA256", "SHA-512", "SHA512", "CHACHA"]):
        base = 5.0
    else:
        base = 10.0

    # Exposure weight (0 - 25)
    if exposure == "Critical":
        exposure_weight = 25.0
    elif exposure == "Externally Exposed":
        exposure_weight = 20.0
    elif exposure == "Internal-only":
        exposure_weight = 5.0
    elif exposure == "Test-only" or is_test_context:
        exposure_weight = -25.0
    else:
        exposure_weight = 0.0

    # Confidence multiplier (0.7 - 1.0)
    conf_str = str(confidence).lower()
    if "single" in conf_str or "medium" in conf_str:
        conf_mult = 0.7
    else:
        conf_mult = 1.0

    raw = (base + max(0.0, exposure_weight)) * conf_mult
    
    # If in test context, downweight with floor at 2.0 so findings remain visible
    if exposure == "Test-only" or is_test_context:
        raw = max(2.0, raw - 25.0)

    score = max(0.0, min(100.0, raw))
    return round(score, 1)

def explain_risk_score(
    algorithm: str,
    exposure: str,
    confidence: str = "High (Dual-Engine)",
    is_test_context: bool = False
) -> Dict[str, Any]:
    """
    Provides full mathematical explainability for why the continuous 0-100 risk score was assigned.
    """
    algo_upper = algorithm.upper()
    
    # Base severity
    if any(k in algo_upper for k in ["HARDCODED", "DES", "RC4", "ARC4"]):
        base = 50.0
        base_desc = "Broken symmetric cipher / hardcoded secret (Base severity: 50/50)"
    elif "WEAK RSA" in algo_upper:
        base = 45.0
        base_desc = "Weak RSA key length <2048 bits (Base severity: 45/50)"
    elif any(k in algo_upper for k in ["MD5", "SHA1", "SHA-1", "VULNERABLE DEPENDENCY"]):
        base = 40.0
        base_desc = "Deprecated/broken hash or vulnerable dependency (Base severity: 40/50)"
    elif any(k in algo_upper for k in ["RSA", "ECC", "ECDSA", "ECDH", "DSA", "DH"]):
        base = 25.0
        base_desc = "Classically secure, quantum-vulnerable public key crypto (Base severity: 25/50)"
    elif any(k in algo_upper for k in ["AES", "SHA-256", "SHA256", "SHA-512", "SHA512", "CHACHA"]):
        base = 5.0
        base_desc = "Modern NIST-approved cryptographic primitive (Base severity: 5/50)"
    else:
        base = 10.0
        base_desc = "Standard cryptographic primitive (Base severity: 10/50)"

    # Exposure weight
    if exposure == "Critical":
        exposure_weight = 25.0
        exp_desc = "+25 pts (Critical security path / authentication context)"
    elif exposure == "Externally Exposed":
        exposure_weight = 20.0
        exp_desc = "+20 pts (Direct network / route exposure)"
    elif exposure == "Internal-only":
        exposure_weight = 5.0
        exp_desc = "+5 pts (Internal non-exposed module)"
    elif exposure == "Test-only" or is_test_context:
        exposure_weight = -25.0
        exp_desc = "-25 pts (Test-only file downweighting)"
    else:
        exposure_weight = 0.0
        exp_desc = "+0 pts (Unclassified exposure)"

    # Confidence multiplier
    conf_str = str(confidence).lower()
    if "single" in conf_str or "medium" in conf_str:
        conf_mult = 0.7
        conf_desc = "0.7x multiplier (Single-engine detection)"
    else:
        conf_mult = 1.0
        conf_desc = "1.0x multiplier (Dual-engine consensus: Semgrep + AST)"

    raw = (base + max(0.0, exposure_weight)) * conf_mult
    if exposure == "Test-only" or is_test_context:
        raw = max(2.0, raw - 25.0)

    score = round(max(0.0, min(100.0, raw)), 1)
    
    if exposure == "Test-only" or is_test_context:
        formula = f"(Base {int(base)} pts) × {conf_mult}x - 25 pts (Test context) = {score}/100"
    else:
        formula = f"(Base {int(base)} pts + Exposure {int(exposure_weight)} pts) × {conf_mult}x = {score}/100"

    summary = (
        f"Score {score}/100 derived from: {base_desc}, "
        f"{exp_desc}, and {conf_desc}. Formula: {formula}"
    )

    return {
        "score": score,
        "base_severity": base,
        "base_desc": base_desc,
        "exposure_weight": exposure_weight,
        "exposure_desc": exp_desc,
        "confidence_multiplier": conf_mult,
        "confidence_desc": conf_desc,
        "formula": formula,
        "summary": summary
    }


