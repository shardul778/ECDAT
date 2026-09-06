import hashlib, os, sys, time, logging
from typing import Dict, Any, List, Optional, Callable

def generate_checksum_via_aliased_function(payload: bytes) -> str:
    """
    Demonstrates Dual-Engine Cross-Validation & Disagreement:
    The weak crypto function is assigned to a local variable alias.
    Semgrep's standard AST pattern (hashlib.md5(...)) does NOT match direct variable calls.
    Python AST scanner resolves the variable alias and flags it!
    
    Result: Single-Engine Detection -> Confidence: Medium (engines: ['ast'])
    """
    md5_func_alias = hashlib.md5
    digest = md5_func_alias(payload).hexdigest()
    return digest

# ==============================================================================
# ALIASED CRYPTOGRAPHIC DISPATCHER (crypto/aliased_crypto.py)
# 
# DUAL-ENGINE CROSS-VALIDATION & DISAGREEMENT ARCHITECTURE:
# ------------------------------------------------------------------------------
# 1. Purpose: Tests engine cross-validation and scanner disagreement.
# 2. Mechanism: `hashlib.md5` is assigned to a local function pointer variable.
# 3. Comment Testing: Mentions of SHA1, DES, RC4, RSA-1024 without calls.
# ==============================================================================

logger = logging.getLogger("crypto.aliased")

class DynamicHashingRegistry:
    """
    Registry providing dynamic function pointers for hashing operations.
    Comment reference: Does not use DES, RC4, or SHA1 in default dispatcher.
    """
    def __init__(self):
        self._dispatch_map: Dict[str, Callable[[bytes], Any]] = {
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512
        }

    def register_custom_hasher(self, name: str, fn: Callable[[bytes], Any]) -> None:
        self._dispatch_map[name] = fn

    def execute_hash(self, name: str, data: bytes) -> Optional[str]:
        fn = self._dispatch_map.get(name)
        if not fn:
            logger.error("Hasher '%s' not registered in dynamic registry.", name)
            return None
        return fn(data).hexdigest()

_REGISTRY = DynamicHashingRegistry()

def compute_safe_sha256_alias(payload: bytes) -> str:
    """
    Safe aliased function pointer using SHA-256.
    """
    sha256_alias = hashlib.sha256
    return sha256_alias(payload).hexdigest()

def batch_process_aliased_hashes(payloads: List[bytes]) -> List[str]:
    """
    Processes multiple byte arrays via dynamic aliasing pipeline.
    """
    results = []
    for item in payloads:
        results.append(compute_safe_sha256_alias(item))
    return results

# End of crypto/aliased_crypto.py module (200+ lines)
