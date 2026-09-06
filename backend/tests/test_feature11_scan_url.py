import os
import re
import tempfile
import shutil
import subprocess
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from backend.main import app, get_dir_size_mb
from backend.database import init_db

@pytest.fixture(autouse=True)
def setup_test_db(monkeypatch):
    temp_dir = tempfile.mkdtemp()
    temp_db_path = os.path.join(temp_dir, "test_url_scan_findings.db")
    monkeypatch.setenv("ECDAT_DB_PATH", temp_db_path)
    init_db(temp_db_path)
    yield temp_db_path
    if os.path.exists(temp_db_path):
        os.remove(temp_db_path)

client = TestClient(app)

def test_tc3_invalid_and_malformed_urls():
    """TC3: Malformed / non-GitHub URL returns 400"""
    bad_urls = [
        "https://gitlab.com/owner/repo",
        "https://bitbucket.org/owner/repo",
        "http://github.com/owner/repo",  # not https
        "https://github.com/",
        "https://github.com/onlyowner",
        "not_a_url",
        "https://evil.com/github.com/owner/repo",
        "https://github.com/owner/repo/extra/path",
    ]
    for url in bad_urls:
        response = client.post("/scan-url", json={"repo_url": url})
        assert response.status_code == 400, f"Expected 400 for {url}, got {response.status_code}"
        assert "Invalid GitHub repository URL" in response.json()["detail"]

def test_tc4_private_or_nonexistent_repo():
    """TC4: Private or non-existent repo returns 404"""
    fake_url = "https://github.com/ecdat-test-org-nonexistent/definitely-not-a-real-repo-12345"
    response = client.post("/scan-url", json={"repo_url": fake_url})
    assert response.status_code in (404, 400)
    if response.status_code == 404:
        assert "not found or private" in response.json()["detail"].lower()

def test_tc5_size_limit_exceeded():
    """TC5: Repo > 50MB rejected with HTTP 413"""
    with patch("backend.main.subprocess.run") as mock_run, \
         patch("backend.main.get_dir_size_mb", return_value=55.4):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        
        response = client.post("/scan-url", json={"repo_url": "https://github.com/owner/large-repo"})
        assert response.status_code == 413
        assert "exceeds the maximum allowed limit of 50MB" in response.json()["detail"]

def test_tc6_clone_timeout():
    """TC6: Timeout simulation at 60s returns HTTP 408"""
    with patch("backend.main.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="git clone", timeout=60)):
        response = client.post("/scan-url", json={"repo_url": "https://github.com/owner/slow-repo"})
        assert response.status_code == 408
        assert "timed out" in response.json()["detail"].lower()

def test_tc1_and_cleanup_temp_dir():
    """TC1: Valid scan with weak crypto and verification of temp directory cleanup"""
    temp_remote = tempfile.mkdtemp(prefix="fake_remote_")
    subprocess.run(["git", "init", temp_remote], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    py_file = os.path.join(temp_remote, "crypto_service.py")
    with open(py_file, "w", encoding="utf-8") as f:
        f.write("import hashlib\nh = hashlib.md5(b'test').hexdigest()\n")
    
    subprocess.run(["git", "-C", temp_remote, "config", "user.name", "TestUser"], check=True)
    subprocess.run(["git", "-C", temp_remote, "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", temp_remote, "add", "."], check=True)
    subprocess.run(["git", "-C", temp_remote, "commit", "-m", "initial commit"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    original_run = subprocess.run
    created_temp_dirs = []

    def fake_subprocess_run(cmd, *args, **kwargs):
        if isinstance(cmd, list) and len(cmd) >= 5 and cmd[0] == "git" and cmd[1] == "clone":
            created_temp_dirs.append(cmd[5])
            clone_cmd = ["git", "clone", "--depth", "1", temp_remote, cmd[5]]
            return original_run(clone_cmd, *args, **kwargs)
        return original_run(cmd, *args, **kwargs)

    try:
        with patch("backend.main.subprocess.run", side_effect=fake_subprocess_run):
            response = client.post("/scan-url", json={"repo_url": "https://github.com/sample/crypto-app"})
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["total_findings"] >= 1
            assert any(f["algorithm"] == "MD5" for f in data["findings"])
            
            for td in created_temp_dirs:
                assert not os.path.exists(td), f"Temp dir {td} was not cleaned up!"
    finally:
        shutil.rmtree(temp_remote, ignore_errors=True)

def test_tc2_zero_python_files():
    """TC2: Valid repo with 0 Python files returns 0 findings"""
    temp_remote = tempfile.mkdtemp(prefix="fake_empty_remote_")
    subprocess.run(["git", "init", temp_remote], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    with open(os.path.join(temp_remote, "README.md"), "w", encoding="utf-8") as f:
        f.write("# Empty Crypto Project\nNo Python files here.\n")
    
    subprocess.run(["git", "-C", temp_remote, "config", "user.name", "TestUser"], check=True)
    subprocess.run(["git", "-C", temp_remote, "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", temp_remote, "add", "."], check=True)
    subprocess.run(["git", "-C", temp_remote, "commit", "-m", "initial commit"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    original_run = subprocess.run
    def fake_subprocess_run(cmd, *args, **kwargs):
        if isinstance(cmd, list) and len(cmd) >= 5 and cmd[0] == "git" and cmd[1] == "clone":
            clone_cmd = ["git", "clone", "--depth", "1", temp_remote, cmd[5]]
            return original_run(clone_cmd, *args, **kwargs)
        return original_run(cmd, *args, **kwargs)

    try:
        with patch("backend.main.subprocess.run", side_effect=fake_subprocess_run):
            response = client.post("/scan-url", json={"repo_url": "https://github.com/sample/no-python-app"})
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["total_findings"] == 0
            assert len(data["findings"]) == 0
    finally:
        shutil.rmtree(temp_remote, ignore_errors=True)

def test_tc7_sample_repo_scan_flow():
    """TC7: Existing sample_repo POST /scan flow returns all findings untouched"""
    response = client.post("/scan")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["target_directory"] == "sample_repo"
    assert data["total_findings"] >= 5
    assert len(data["findings"]) == data["total_findings"]

def test_tc8_concurrent_requests_isolation():
    """TC8: Concurrent requests use distinct temporary directories (UUID isolation)"""
    import threading
    results = {}
    temp_dirs_observed = []
    lock = threading.Lock()

    def fake_subprocess_run(cmd, *args, **kwargs):
        if isinstance(cmd, list) and len(cmd) >= 5 and cmd[0] == "git" and cmd[1] == "clone":
            with lock:
                temp_dirs_observed.append(cmd[5])
            # Return fake failure after capturing path to test directory generation quickly
            return MagicMock(returncode=1, stderr="repository not found")
        return MagicMock(returncode=1, stderr="mock error")

    def run_req(idx, url):
        c = TestClient(app)
        res = c.post("/scan-url", json={"repo_url": url})
        results[idx] = res.status_code

    with patch("backend.main.subprocess.run", side_effect=fake_subprocess_run):
        threads = [
            threading.Thread(target=run_req, args=(i, f"https://github.com/org/repo-{i}"))
            for i in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    # All temp dirs generated must be unique
    assert len(temp_dirs_observed) == 5
    assert len(set(temp_dirs_observed)) == 5

