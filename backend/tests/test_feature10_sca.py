import os
import tempfile
import pytest
from backend.scanners.sca_scanner import run_sca_scan, scan_file_sca, load_vulnerable_db

def test_vulnerable_dependency_detected():
    """Test Case 1: Vulnerable dependency (pycrypto and pyjwt < 2.0.0) correctly detected."""
    with tempfile.TemporaryDirectory() as temp_dir:
        req_file = os.path.join(temp_dir, "requirements.txt")
        with open(req_file, "w", encoding="utf-8") as f:
            f.write("pycrypto==2.6.1\npyjwt==1.7.1\n")

        vuln_db = load_vulnerable_db()
        findings = scan_file_sca(req_file, temp_dir, vuln_db)

        assert len(findings) == 2
        dep_names = {f["dependency"] for f in findings}
        assert "pycrypto" in dep_names
        assert "pyjwt" in dep_names
        
        pycrypto_f = next(f for f in findings if f["dependency"] == "pycrypto")
        assert pycrypto_f["line"] == 1
        assert "pycrypto" in pycrypto_f["algorithm"].lower()
        assert pycrypto_f["scanner"] == "sca"
        assert "pycryptodome" in pycrypto_f["message"]

def test_safe_unlisted_dependency_ignored():
    """Test Case 2: Safe and unlisted dependencies correctly ignored (no false positives)."""
    with tempfile.TemporaryDirectory() as temp_dir:
        req_file = os.path.join(temp_dir, "requirements.txt")
        with open(req_file, "w", encoding="utf-8") as f:
            f.write(
                "# Modern safe crypto and utility packages\n"
                "cryptography==42.0.0\n"
                "bcrypt==4.1.2\n"
                "pyjwt==2.8.0\n"  # pyjwt >= 2.0.0 is safe
                "requests==2.31.0\n"
            )

        vuln_db = load_vulnerable_db()
        findings = scan_file_sca(req_file, temp_dir, vuln_db)

        # pyjwt 2.8.0 >= 2.0.0 and cryptography/bcrypt/requests are safe -> 0 findings
        assert len(findings) == 0

def test_package_json_sca_detection():
    """Test Case 3: JavaScript package.json vulnerable dependencies (jsrsasign < 10.5.0)."""
    with tempfile.TemporaryDirectory() as temp_dir:
        pkg_file = os.path.join(temp_dir, "package.json")
        with open(pkg_file, "w", encoding="utf-8") as f:
            f.write('{\n  "dependencies": {\n    "jsrsasign": "8.0.24",\n    "react": "^18.2.0"\n  }\n}')

        vuln_db = load_vulnerable_db()
        findings = scan_file_sca(pkg_file, temp_dir, vuln_db)

        assert len(findings) == 1
        assert findings[0]["dependency"] == "jsrsasign"
        assert findings[0]["scanner"] == "sca"
