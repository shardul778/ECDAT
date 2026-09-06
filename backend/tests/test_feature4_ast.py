import os
import tempfile
import pytest
from backend.scanners.ast_scanner import run_ast_scan, scan_file_ast

@pytest.fixture
def temp_ast_test_dir():
    temp_dir = tempfile.mkdtemp()
    
    # 1. MD5 file
    with open(os.path.join(temp_dir, "auth_md5.py"), "w") as f:
        f.write("import hashlib\n\ndef hash_pw(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n")

    # 2. SHA1 file
    with open(os.path.join(temp_dir, "tokens.py"), "w") as f:
        f.write("import hashlib\n\ndef tok(t):\n    return hashlib.new('sha1', t.encode()).hexdigest()\n")

    # 3. DES file
    with open(os.path.join(temp_dir, "legacy_des.py"), "w") as f:
        f.write("from Crypto.Cipher import DES\n\ndef enc(k, d):\n    c = DES.new(k, DES.MODE_ECB)\n    return c.encrypt(d)\n")

    # 4. RC4 file
    with open(os.path.join(temp_dir, "stream_rc4.py"), "w") as f:
        f.write("from Crypto.Cipher import ARC4\n\ndef stream(k, d):\n    c = ARC4.new(k)\n    return c.encrypt(d)\n")

    # 5. Hardcoded key
    with open(os.path.join(temp_dir, "config.py"), "w") as f:
        f.write("api_secret_key = 'sk_live_1234567890abcdef'\n")

    # 6. Weak RSA vs Strong RSA
    with open(os.path.join(temp_dir, "rsa_keys.py"), "w") as f:
        f.write("from Crypto.PublicKey import RSA\n\nk1 = RSA.generate(1024)\nk2 = RSA.generate(4096)\n")

    # 7. Safe crypto
    with open(os.path.join(temp_dir, "safe_crypto.py"), "w") as f:
        f.write("import hashlib\n\ndef hash_sha256(data):\n    return hashlib.sha256(data.encode()).hexdigest()\n")

    # 8. Syntax error file
    with open(os.path.join(temp_dir, "broken_syntax.py"), "w") as f:
        f.write("def broken(:\n    pass\n")

    yield temp_dir

def test_ast_scan_detects_all_vulnerabilities(temp_ast_test_dir):
    findings = run_ast_scan(temp_ast_test_dir)
    algorithms = {f["algorithm"] for f in findings}
    
    assert "MD5" in algorithms
    assert "SHA1" in algorithms
    assert "DES" in algorithms
    assert "RC4" in algorithms
    assert "Hardcoded Key" in algorithms
    assert "Weak RSA (<2048)" in algorithms
    assert "RSA (>=2048)" in algorithms

    # Safe file shouldn't produce findings
    files = {f["file"] for f in findings}
    assert "safe_crypto.py" not in files
    assert "broken_syntax.py" not in files

def test_ast_scan_rsa_key_sizes(temp_ast_test_dir):
    findings = scan_file_ast(os.path.join(temp_ast_test_dir, "rsa_keys.py"), base_dir=temp_ast_test_dir)
    # Both 1024 (Weak RSA) and 4096 (RSA >=2048 quantum tier) should be captured
    assert len(findings) == 2
    assert findings[0]["algorithm"] == "Weak RSA (<2048)"
    assert findings[0]["line"] == 3
    assert findings[1]["algorithm"] == "RSA (>=2048)"
    assert findings[1]["line"] == 4
