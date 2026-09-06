import json
import os
import subprocess
import shutil
from typing import List, Dict, Any

def get_semgrep_command() -> List[str]:
    semgrep_bin = shutil.which("semgrep")
    if semgrep_bin:
        return [semgrep_bin]
    
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        win_path = os.path.join(appdata, "Python", "Python313", "Scripts", "semgrep.exe")
        if os.path.exists(win_path):
            return [win_path]
        
    return ["semgrep"]

def normalize_algorithm(rule_id: str) -> str:
    rule_lower = rule_id.lower()
    if "md5" in rule_lower:
        return "MD5"
    if "sha1" in rule_lower:
        return "SHA1"
    if "des" in rule_lower:
        return "DES"
    if "rc4" in rule_lower or "arc4" in rule_lower:
        return "RC4"
    if "hardcoded" in rule_lower or "secret" in rule_lower:
        return "Hardcoded Key"
    if "weak-rsa" in rule_lower or "rsa-key-size" in rule_lower:
        return "Weak RSA (<2048)"
    if "quantum-vulnerable-rsa" in rule_lower or "rsa" in rule_lower:
        return "RSA (>=2048)"
    return rule_id

def run_semgrep_scan(target_dir: str, rules_path: str) -> List[Dict[str, Any]]:
    """
    Runs semgrep against target_dir using rules_path and returns normalized findings.
    Ensures all subdirectories (including tests/) are scanned without default exclusions.
    """
    # Collect all python target files/directories to prevent Semgrep's default test exclusions
    target_paths = []
    for root, dirs, files in os.walk(target_dir):
        for f in files:
            if f.endswith(".py"):
                target_paths.append(os.path.join(root, f))
                
    if not target_paths:
        target_paths = [target_dir]

    cmd = get_semgrep_command() + [
        "--config", rules_path,
        "--json",
        "--quiet",
        "--disable-version-check",
        "--metrics=off"
    ] + target_paths
    
    env = os.environ.copy()
    env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
    user_scripts = os.path.join(env.get("APPDATA", ""), "Python", "Python313", "Scripts")
    if os.path.exists(user_scripts):
        env["PATH"] = user_scripts + os.pathsep + env.get("PATH", "")

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env=env,
            timeout=60
        )
        output = proc.stdout.strip()
        if not output:
            return []
        
        data = json.loads(output)
        results = data.get("results", [])
        
        findings = []
        for r in results:
            raw_path = r.get("path", "")
            file_path = os.path.relpath(raw_path, target_dir).replace("\\", "/")
            line_num = r.get("start", {}).get("line", 1)
            check_id = r.get("check_id", "")
            message = r.get("extra", {}).get("message", "")
            
            findings.append({
                "scanner": "semgrep",
                "file": file_path,
                "line": line_num,
                "algorithm": normalize_algorithm(check_id),
                "rule_id": check_id,
                "message": message
            })
        return findings
    except Exception as e:
        print(f"Semgrep execution error: {e}")
        return []
