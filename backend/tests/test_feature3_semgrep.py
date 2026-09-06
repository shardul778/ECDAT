import os
import tempfile
import pytest
from backend.scanners.semgrep_scanner import run_semgrep_scan, normalize_algorithm

RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "rules", "crypto_rules.yaml")

@pytest.fixture
def temp_vulnerable_code():
    temp_dir = tempfile.mkdtemp()
    
    # Plant MD5
    with open(os.path.join(temp_dir, "test_md5.py"), "w") as f:
        f.write("import hashlib\n\ndef hash_user(pwd):\n    return hashlib.md5(pwd.encode()).hexdigest()\n")
        
    # Plant SHA1
    with open(os.path.join(temp_dir, "test_sha1.py"), "w") as f:
        f.write("import hashlib\n\ndef verify_token(tok):\n    return hashlib.sha1(tok.encode()).hexdigest()\n")

    # Plant DES
    with open(os.path.join(temp_dir, "test_des.py"), "w") as f:
        f.write("from Crypto.Cipher import DES\n\ndef encrypt_data(key, data):\n    cipher = DES.new(key, DES.MODE_ECB)\n    return cipher.encrypt(data)\n")

    # Plant RC4
    with open(os.path.join(temp_dir, "test_rc4.py"), "w") as f:
        f.write("from Crypto.Cipher import ARC4\n\ndef encrypt_rc4(key, data):\n    cipher = ARC4.new(key)\n    return cipher.encrypt(data)\n")

    # Plant Hardcoded Secret Key
    with open(os.path.join(temp_dir, "test_keys.py"), "w") as f:
        f.write("secret_key = 'super_secret_master_key_12345'\n")

    # Plant Weak RSA
    with open(os.path.join(temp_dir, "test_rsa.py"), "w") as f:
        f.write("from Crypto.PublicKey import RSA\n\ndef gen_key():\n    return RSA.generate(1024)\n")

    # Plant Safe Modern Crypto (SHA256)
    with open(os.path.join(temp_dir, "test_safe.py"), "w") as f:
        f.write("import hashlib\n\ndef safe_hash(data):\n    return hashlib.sha256(data.encode()).hexdigest()\n")

    yield temp_dir

def test_normalize_algorithm():
    assert normalize_algorithm("rules.weak-crypto-md5") == "MD5"
    assert normalize_algorithm("rules.weak-crypto-sha1") == "SHA1"
    assert normalize_algorithm("rules.weak-crypto-des") == "DES"
    assert normalize_algorithm("rules.weak-crypto-rc4") == "RC4"
    assert normalize_algorithm("rules.hardcoded-secret-key") == "Hardcoded Key"
    assert normalize_algorithm("rules.weak-rsa-key-size") == "Weak RSA (<2048)"

def test_semgrep_scanner_detects_all_vulnerabilities(temp_vulnerable_code):
    findings = run_semgrep_scan(temp_vulnerable_code, RULES_PATH)
    algorithms_found = {f["algorithm"] for f in findings}
    
    assert "MD5" in algorithms_found
    assert "SHA1" in algorithms_found
    assert "DES" in algorithms_found
    assert "RC4" in algorithms_found
    assert "Hardcoded Key" in algorithms_found
    assert "Weak RSA (<2048)" in algorithms_found

    # Safe file shouldn't produce findings
    files_with_findings = {f["file"] for f in findings}
    assert "test_safe.py" not in files_with_findings
