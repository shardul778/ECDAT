import ast
import os
import re
from typing import List, Dict, Any, Optional

SECRET_NAME_PATTERN = re.compile(
    r".*(api_key|secret_key|private_key|access_key|auth_key|password|passwd|pwd|token|access_token|auth_token|client_secret|api_secret|encryption_key).*",
    re.IGNORECASE
)

PLACEHOLDER_VALUES = {
    "test", "testing", "changeme", "example", "placeholder", "todo", "fixme",
    "xxx", "xxxx", "none", "null", "", "password", "123456", "admin", "secret",
    "dummy", "sample", "demo", "temp", "mock"
}

def is_hardcoded_secret(var_name: str, val_str: str) -> bool:
    if not var_name or not isinstance(val_str, str):
        return False
    # 1. Variable name match
    if not SECRET_NAME_PATTERN.match(var_name):
        return False
    # 2. Length >= 12
    val_clean = val_str.strip()
    if len(val_clean) < 12:
        return False
    # 3. Not a placeholder (case-insensitive exact match)
    if val_clean.lower() in PLACEHOLDER_VALUES:
        return False
    # 4. At least one letter AND at least one digit
    has_letter = any(c.isalpha() for c in val_clean)
    has_digit = any(c.isdigit() for c in val_clean)
    if not (has_letter and has_digit):
        return False
    return True

class CryptoASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: List[Dict[str, Any]] = []
        self.aliases: Dict[str, str] = {}

    def _get_call_name(self, node: ast.AST) -> str:
        """Helper to get full dotted call name, e.g. hashlib.md5 or DES.new"""
        parts = []
        curr = node
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
            
        full_name = ".".join(reversed(parts))
        # Check alias resolution
        if full_name in self.aliases:
            return self.aliases[full_name]
        return full_name

    def visit_Assign(self, node: ast.Assign):
        # Track function aliasing (e.g. m = hashlib.md5 or c = DES.new)
        call_val_name = self._get_call_name(node.value)
        if call_val_name:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.aliases[target.id] = call_val_name

        # Hardcoded Secret Key detection
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                target_id = None
                if isinstance(target, ast.Name):
                    target_id = target.id
                elif isinstance(target, ast.Attribute):
                    target_id = target.attr
                
                if target_id and is_hardcoded_secret(target_id, node.value.value):
                    self.findings.append({
                        "scanner": "ast",
                        "file": self.file_path,
                        "line": node.lineno,
                        "algorithm": "Hardcoded Key",
                        "rule_id": "ast-hardcoded-secret-key",
                        "message": f"Hardcoded secret assignment to '{target_id}' detected by AST scanner."
                    })
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        call_name = self._get_call_name(node.func)
        
        # 1. MD5
        if call_name in ("hashlib.md5", "Crypto.Hash.MD5.new", "Cryptodome.Hash.MD5.new", "MD5.new"):
            self.findings.append({
                "scanner": "ast",
                "file": self.file_path,
                "line": node.lineno,
                "algorithm": "MD5",
                "rule_id": "ast-weak-crypto-md5",
                "message": "Weak cryptographic hash function MD5 detected by AST scanner."
            })
        elif call_name == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant) and str(node.args[0].value).lower() == "md5":
            self.findings.append({
                "scanner": "ast",
                "file": self.file_path,
                "line": node.lineno,
                "algorithm": "MD5",
                "rule_id": "ast-weak-crypto-md5",
                "message": "Weak cryptographic hash function MD5 detected by AST scanner."
            })

        # 2. SHA1
        elif call_name in ("hashlib.sha1", "Crypto.Hash.SHA1.new", "Cryptodome.Hash.SHA1.new", "SHA1.new"):
            self.findings.append({
                "scanner": "ast",
                "file": self.file_path,
                "line": node.lineno,
                "algorithm": "SHA1",
                "rule_id": "ast-weak-crypto-sha1",
                "message": "Weak cryptographic hash function SHA1 detected by AST scanner."
            })
        elif call_name == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant) and str(node.args[0].value).lower() == "sha1":
            self.findings.append({
                "scanner": "ast",
                "file": self.file_path,
                "line": node.lineno,
                "algorithm": "SHA1",
                "rule_id": "ast-weak-crypto-sha1",
                "message": "Weak cryptographic hash function SHA1 detected by AST scanner."
            })

        # 3. DES
        elif call_name in (
            "Crypto.Cipher.DES.new", "Cryptodome.Cipher.DES.new", "DES.new", "pyDes.des", "des.new"
        ):
            self.findings.append({
                "scanner": "ast",
                "file": self.file_path,
                "line": node.lineno,
                "algorithm": "DES",
                "rule_id": "ast-weak-crypto-des",
                "message": "Weak cryptographic cipher DES detected by AST scanner."
            })

        # 4. RC4 / ARC4
        elif call_name in (
            "Crypto.Cipher.ARC4.new", "Cryptodome.Cipher.ARC4.new", "ARC4.new", "rc4", "arc4"
        ):
            self.findings.append({
                "scanner": "ast",
                "file": self.file_path,
                "line": node.lineno,
                "algorithm": "RC4",
                "rule_id": "ast-weak-crypto-rc4",
                "message": "Broken cryptographic cipher RC4 detected by AST scanner."
            })

        # 5. RSA (Weak <2048 vs Quantum-vulnerable >=2048)
        elif call_name in (
            "RSA.generate", "Crypto.PublicKey.RSA.generate", "Cryptodome.PublicKey.RSA.generate",
            "rsa.generate_private_key"
        ):
            key_size = None
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, int):
                key_size = node.args[0].value
            for kw in node.keywords:
                if kw.arg in ("bits", "key_size") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                    key_size = kw.value.value

            if key_size is not None:
                if key_size < 2048:
                    self.findings.append({
                        "scanner": "ast",
                        "file": self.file_path,
                        "line": node.lineno,
                        "algorithm": "Weak RSA (<2048)",
                        "rule_id": "ast-weak-rsa-key-size",
                        "message": f"Weak RSA key size ({key_size} bits < 2048) detected by AST scanner."
                    })
                else:
                    self.findings.append({
                        "scanner": "ast",
                        "file": self.file_path,
                        "line": node.lineno,
                        "algorithm": "RSA (>=2048)",
                        "rule_id": "ast-quantum-vulnerable-rsa",
                        "message": f"RSA key size ({key_size} bits >= 2048) is classically secure but quantum-vulnerable."
                    })

        self.generic_visit(node)

def scan_file_ast(file_path: str, base_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
        if not source.strip():
            return []
        tree = ast.parse(source, filename=file_path)
        rel_path = os.path.relpath(file_path, base_dir).replace("\\", "/") if base_dir else file_path
        visitor = CryptoASTVisitor(rel_path)
        visitor.visit(tree)
        return visitor.findings
    except SyntaxError as syn_err:
        print(f"Skipping malformed file (syntax error): {file_path}")
        return []
    except Exception as e:
        print(f"AST scan error for {file_path}: {e}")
        return []

def run_ast_scan(target_dir: str) -> List[Dict[str, Any]]:
    findings = []
    for root, _, files in os.walk(target_dir):
        for file in files:
            if file.endswith(".py"):
                full_path = os.path.join(root, file)
                findings.extend(scan_file_ast(full_path, base_dir=target_dir))
    return findings
