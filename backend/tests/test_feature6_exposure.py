import os
import tempfile
import pytest
from backend.pipeline.exposure import tag_exposure

@pytest.fixture
def temp_exposure_files():
    temp_dir = tempfile.mkdtemp()

    # 1. Critical path file
    auth_dir = os.path.join(temp_dir, "auth")
    os.makedirs(auth_dir, exist_ok=True)
    auth_file = os.path.join(auth_dir, "login.py")
    with open(auth_file, "w") as f:
        f.write("def login():\n    pass\n")

    # 2. Externally exposed route file
    api_dir = os.path.join(temp_dir, "api")
    os.makedirs(api_dir, exist_ok=True)
    api_file = os.path.join(api_dir, "routes.py")
    with open(api_file, "w") as f:
        f.write(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n\n"
            "@app.post('/process')\n"
            "def process_data(payload):\n"
            "    cipher = 'DES'\n"
            "    return {'status': 'ok'}\n\n"
            "def internal_helper():\n"
            "    return 42\n"
        )

    # 3. Internal utility file
    util_file = os.path.join(temp_dir, "utils.py")
    with open(util_file, "w") as f:
        f.write("def helper():\n    return 'secret'\n")

    yield temp_dir

def test_critical_path_tagging(temp_exposure_files):
    exposure, reason = tag_exposure("auth/login.py", 1, temp_exposure_files)
    assert exposure == "Critical"
    assert "auth" in reason

def test_externally_exposed_route_tagging(temp_exposure_files):
    # Line 6 is inside @app.post function
    exposure, reason = tag_exposure("api/routes.py", 6, temp_exposure_files)
    assert exposure == "Externally Exposed"
    assert "process_data" in reason

def test_internal_only_tagging(temp_exposure_files):
    exposure, reason = tag_exposure("utils.py", 2, temp_exposure_files)
    assert exposure == "Internal-only"

def test_test_only_tagging_confidence_reasons(temp_exposure_files):
    # Dual-Engine confidence
    exp_dual, reason_dual = tag_exposure("tests/test_foo.py", 5, temp_exposure_files, confidence="High (Dual-Engine)")
    assert exp_dual == "Test-only"
    assert "both engines agree" in reason_dual

    # Single-Engine confidence
    exp_single, reason_single = tag_exposure("tests/test_foo.py", 5, temp_exposure_files, confidence="Medium (Single-Engine)")
    assert exp_single == "Test-only"
    assert "by one engine only" in reason_single
