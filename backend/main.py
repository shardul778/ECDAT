import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any

from backend.database import init_db, clear_findings, insert_findings_batch, get_all_findings
from backend.pipeline.orchestrator import run_ecdat_pipeline
from backend.pipeline.cbom import generate_cbom

# Path to preloaded sample repo
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="ECDAT - Enterprise Cryptographic Discovery & Analysis Tool",
    version="1.0.0",
    description="Scan Python source code for weak and quantum-vulnerable cryptography",
    lifespan=lifespan
)

# CORS Configuration (Feature 16)
origins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {
        "status": "online",
        "service": "ECDAT Backend API",
        "version": "1.0.0"
    }

@app.get("/health")
def health_check():
    return {"status": "healthy"}

import re
import uuid
import shutil
import tempfile
import subprocess
from pydantic import BaseModel

class ScanUrlRequest(BaseModel):
    repo_url: str

import stat

def _force_remove_readonly(func, path, exc_info):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass

def get_dir_size_mb(path: str) -> float:
    total_bytes = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                total_bytes += os.path.getsize(fp)
            except OSError:
                pass
    return total_bytes / (1024 * 1024)

@app.post("/scan-url")
def scan_url(request: ScanUrlRequest):
    """
    Clones a public GitHub repository, runs the full ECDAT pipeline, and cleans up.
    """
    repo_url = request.repo_url.strip()
    
    # 1. URL validation: Must match https://github.com/<owner>/<repo>
    github_pattern = r"^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(\.git)?$"
    if not re.match(github_pattern, repo_url):
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub repository URL. Must be in the format 'https://github.com/<owner>/<repo>'."
        )

    # 2. Temporary directory with unique UUID
    temp_dir = os.path.join(tempfile.gettempdir(), f"ecdat_scan_{uuid.uuid4()}")
    
    try:
        # 3. Clone with 60s timeout
        start_time = os.times().elapsed
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, temp_dir],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(
                status_code=408,
                detail="Cloning timed out. Operation exceeded 60-second limit."
            )
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to execute git clone: {str(e)}"
            )

        if result.returncode != 0:
            stderr_lower = result.stderr.lower()
            if "not found" in stderr_lower or "authentication" in stderr_lower or "could not read username" in stderr_lower:
                raise HTTPException(
                    status_code=404,
                    detail="Repository not found or private. Please ensure the repository is public and the URL is correct."
                )
            raise HTTPException(
                status_code=400,
                detail=f"Git clone failed: {result.stderr.strip()}"
            )

        # 4. Check repository size limit (50MB)
        size_mb = get_dir_size_mb(temp_dir)
        if size_mb > 50.0:
            raise HTTPException(
                status_code=413,
                detail=f"Repository size ({size_mb:.1f}MB) exceeds the maximum allowed limit of 50MB."
            )

        # 5. Run existing pipeline
        findings = run_ecdat_pipeline(temp_dir)

        # Store findings in SQLite for consistent dashboard views
        clear_findings()
        insert_findings_batch(findings)

        db_findings = get_all_findings()
        return {
            "status": "success",
            "total_findings": len(db_findings),
            "target_directory": repo_url,
            "findings": db_findings
        }
    finally:
        # 6. Always clean up temporary clone directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, onerror=_force_remove_readonly)
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

@app.post("/scan")
def trigger_scan():
    """
    Executes full pipeline on pre-loaded sample repo, stores findings in SQLite,
    and returns findings.
    """
    sample_repo_dir = os.environ.get("ECDAT_SAMPLE_REPO", os.path.join(BASE_DIR, "sample_repo"))
    if not os.path.exists(sample_repo_dir):
        raise HTTPException(status_code=404, detail=f"Sample repo directory not found at {sample_repo_dir}")

    findings = run_ecdat_pipeline(sample_repo_dir)
    
    # Store findings in SQLite
    clear_findings()
    insert_findings_batch(findings)
    
    # Return stored findings with database IDs
    db_findings = get_all_findings()
    return {
        "status": "success",
        "total_findings": len(db_findings),
        "target_directory": "sample_repo",
        "findings": db_findings
    }

@app.get("/findings")
def list_findings():
    """
    Returns stored findings from SQLite database.
    """
    findings = get_all_findings()
    return {
        "status": "success",
        "total_findings": len(findings),
        "findings": findings
    }

@app.get("/export/cbom")
def export_cbom():
    """
    Generates and returns CBOM-style JSON export of current findings.
    """
    findings = get_all_findings()
    cbom_data = generate_cbom(findings)
    return cbom_data

@app.get("/snippet")
def get_code_snippet(file: str, line: int, context_lines: int = 2):
    """
    Returns source code snippet around the target line (± context_lines).
    If file is not accessible, returns status 'unavailable' gracefully without raising a 500 error.
    """
    sample_repo_dir = os.environ.get("ECDAT_SAMPLE_REPO", os.path.join(BASE_DIR, "sample_repo"))
    
    if os.path.isabs(file):
        target_file = file
    else:
        target_file = os.path.normpath(os.path.join(sample_repo_dir, file))
        
    if not os.path.exists(target_file) or not os.path.isfile(target_file):
        return {
            "status": "unavailable",
            "message": "Source snippet unavailable",
            "file": file,
            "line": line,
            "lines": []
        }
        
    try:
        with open(target_file, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
            
        total_file_lines = len(all_lines)
        if total_file_lines == 0 or line < 1 or line > total_file_lines:
            return {
                "status": "unavailable",
                "message": "Source snippet unavailable",
                "file": file,
                "line": line,
                "lines": []
            }
            
        start = max(1, line - context_lines)
        end = min(total_file_lines, line + context_lines)
        
        snippet_lines = []
        for l_num in range(start, end + 1):
            snippet_lines.append({
                "line_number": l_num,
                "content": all_lines[l_num - 1].rstrip("\r\n"),
                "is_target": (l_num == line)
            })
            
        return {
            "status": "success",
            "file": file,
            "line": line,
            "start_line": start,
            "end_line": end,
            "lines": snippet_lines
        }
    except Exception as e:
        return {
            "status": "unavailable",
            "message": f"Source snippet unavailable: {str(e)}",
            "file": file,
            "line": line,
            "lines": []
        }
