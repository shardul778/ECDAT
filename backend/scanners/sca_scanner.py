import os
import re
import json
import yaml
from typing import List, Dict, Any, Optional, Tuple

MANIFEST_LANGUAGES = {
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "package.json": "javascript",
    "pom.xml": "java",
    "build.gradle": "java",
}

DEFAULT_RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "rules", "crypto_rules.yaml")

DEFAULT_VULNERABLE_DEPENDENCIES = {
    "python": {
        "pycrypto": {
            "max_safe_version": None,
            "note": "Unmaintained since 2013, multiple CVEs (e.g. CVE-2013-7459). Use pycryptodome."
        },
        "pyjwt": {
            "unsafe_versions": ["<2.0.0"],
            "note": "Older PyJWT allowed algorithm confusion attacks (alg=none)."
        }
    },
    "javascript": {
        "jsrsasign": {
            "unsafe_versions": ["<10.5.0"],
            "note": "Signature validation bypass in older versions."
        },
        "crypto-js": {
            "unsafe_versions": ["<4.0.0"],
            "note": "Weak default configs / PBKDF1 usage in old versions."
        }
    },
    "java": {
        "bouncycastle": {
            "unsafe_versions": ["<1.60"],
            "note": "Multiple padding-oracle / timing CVEs before 1.60."
        }
    }
}

def load_vulnerable_db(rules_path: Optional[str] = None) -> Dict[str, Any]:
    path = rules_path or DEFAULT_RULES_PATH
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict) and "vulnerable_dependencies" in data:
                return data["vulnerable_dependencies"]
        except Exception as e:
            print(f"Warning: Could not parse vulnerable_dependencies from {path}: {e}")
    return DEFAULT_VULNERABLE_DEPENDENCIES

def _parse_requirements_txt(text: str) -> List[Tuple[str, str, int]]:
    """
    Parses requirements.txt returning list of (package_name, version, line_number).
    """
    deps = []
    for line_idx, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*==\s*([0-9][A-Za-z0-9\.\-]*)", line)
        if m:
            deps.append((m.group(1).lower(), m.group(2), line_idx))
        else:
            m2 = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
            if m2:
                deps.append((m2.group(1).lower(), "unpinned", line_idx))
    return deps

def _parse_package_json(text: str) -> List[Tuple[str, str, int]]:
    """
    Parses package.json returning list of (package_name, version, line_number).
    """
    deps = []
    try:
        data = json.loads(text)
    except Exception:
        return deps

    lines = text.splitlines()
    for section in ("dependencies", "devDependencies"):
        for name, ver in data.get(section, {}).items():
            clean_ver = re.sub(r"[^0-9.]", "", ver) or "unpinned"
            line_no = 1
            for idx, l in enumerate(lines, start=1):
                if f'"{name}"' in l or f"'{name}'" in l:
                    line_no = idx
                    break
            deps.append((name.lower(), clean_ver, line_no))
    return deps

def _parse_pom_xml(text: str) -> List[Tuple[str, str, int]]:
    """
    Parses pom.xml returning list of (artifact_id, version, line_number).
    """
    deps = []
    for line_idx, line in enumerate(text.splitlines(), start=1):
        m = re.search(r"<artifactId>([^<]+)</artifactId>", line)
        if m:
            deps.append((m.group(1).lower(), "unpinned", line_idx))
    return deps

def _version_is_unsafe(version: str, constraint: str) -> bool:
    """
    Evaluates version against constraint (e.g. '<2.0.0').
    Unpinned versions are treated as unsafe by default.
    """
    if version in ("unpinned", ""):
        return True
    m = re.match(r"<\s*([0-9]+(?:\.[0-9]+)*)", constraint)
    if not m:
        return False

    def parts(v: str) -> List[int]:
        return [int(x) for x in re.findall(r"\d+", v)]

    v_parts, c_parts = parts(version), parts(m.group(1))
    v_parts += [0] * (len(c_parts) - len(v_parts))
    c_parts += [0] * (len(v_parts) - len(c_parts))
    return v_parts < c_parts

def scan_file_sca(
    file_path: str,
    target_dir: str,
    vuln_db: Dict[str, Any]
) -> List[Dict[str, Any]]:
    findings = []
    filename = os.path.basename(file_path)
    if filename not in MANIFEST_LANGUAGES:
        return []

    lang = MANIFEST_LANGUAGES[filename]
    lang_db = vuln_db.get(lang, {})
    if not lang_db:
        return []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except Exception as e:
        print(f"SCA read error for {file_path}: {e}")
        return []

    if filename == "requirements.txt":
        deps = _parse_requirements_txt(text)
    elif filename == "package.json":
        deps = _parse_package_json(text)
    elif filename == "pom.xml":
        deps = _parse_pom_xml(text)
    else:
        deps = []

    rel_path = os.path.relpath(file_path, target_dir).replace("\\", "/")

    for dep_name, version, line_no in deps:
        if dep_name not in lang_db:
            continue

        dep_info = lang_db[dep_name]
        unsafe_versions = dep_info.get("unsafe_versions")
        is_unconditionally_unsafe = (
            dep_info.get("max_safe_version") in (None, "none", "null") and not unsafe_versions
        )

        is_unsafe = is_unconditionally_unsafe or any(
            _version_is_unsafe(version, c) for c in (unsafe_versions or [])
        )

        if is_unsafe:
            note = dep_info.get("note", "Known vulnerable crypto dependency.")
            findings.append({
                "scanner": "sca",
                "file": rel_path,
                "line": line_no,
                "algorithm": f"Vulnerable Dependency ({dep_name})",
                "rule_id": f"sca-{dep_name}",
                "message": note,
                "dependency": dep_name,
                "version": version
            })

    return findings

def run_sca_scan(target_dir: str, rules_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Runs Software Composition Analysis (SCA) scan across target_dir looking for
    manifest files (requirements.txt, package.json, pom.xml) and flagging vulnerable dependencies.
    """
    vuln_db = load_vulnerable_db(rules_path)
    findings = []

    for root, _, files in os.walk(target_dir):
        for f in files:
            if f in MANIFEST_LANGUAGES:
                full_path = os.path.join(root, f)
                findings.extend(scan_file_sca(full_path, target_dir, vuln_db))

    return findings
