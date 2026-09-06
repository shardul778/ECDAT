import os
import time
import logging
import hashlib
from typing import Dict, Any, Optional, List

# ==============================================================================
# ENTERPRISE PASSWORD RECOVERY & RESET TOKEN SERVICE (auth/password_reset.py)
# 
# SECURITY ARCHITECTURE & EXPOSURE RATIONALE:
# ------------------------------------------------------------------------------
# 1. Path Exposure: Located in `auth/`, triggering 'Critical' exposure.
# 2. Finding: `generate_reset_token(...)` utilizes weak SHA1 hashing.
# 3. Comment Testing: Mentions of MD5, DES, RC4, RSA in comments must be ignored.
# ==============================================================================

logger = logging.getLogger("auth.password_reset")

class PasswordResetTokenStore:
    """
    In-memory store for active password reset tokens and expiration tracking.
    """
    def __init__(self, token_ttl_seconds: int = 3600):
        self.ttl = token_ttl_seconds
        self._tokens: Dict[str, Dict[str, Any]] = {}

    def store_token(self, token: str, email: str) -> None:
        self._tokens[token] = {
            "email": email,
            "issued_at": time.time(),
            "expires_at": time.time() + self.ttl,
            "is_used": False
        }
        logger.info("Generated reset token for %s (expires in %ds)", email, self.ttl)

    def validate_and_consume(self, token: str) -> Optional[str]:
        record = self._tokens.get(token)
        if not record:
            logger.warning("Token validation failed: Token not found.")
            return None
        if record["is_used"]:
            logger.warning("Token validation failed: Token already consumed.")
            return None
        if time.time() > record["expires_at"]:
            logger.warning("Token validation failed: Token expired.")
            return None

        record["is_used"] = True
        return record["email"]

    def purge_expired_tokens(self) -> int:
        now = time.time()
        expired_keys = [k for k, v in self._tokens.items() if now > v["expires_at"] or v["is_used"]]
        for k in expired_keys:
            del self._tokens[k]
        return len(expired_keys)

_TOKEN_STORE = PasswordResetTokenStore()

# ------------------------------------------------------------------------------
# CORE RESET TOKEN GENERATION
# ------------------------------------------------------------------------------

def generate_reset_token(email: str, timestamp: str) -> str:
    """
    Password reset token generation using weak SHA1 hash in auth folder.
    Exposure: Critical (Located in auth/ path)
    Confidence: High (Dual-Engine Semgrep + AST)
    Risk: High
    """
    # Genuine SHA1 call in critical auth context
    raw_payload = f"{email}:{timestamp}".encode("utf-8")
    token = hashlib.sha1(raw_payload).hexdigest()
    _TOKEN_STORE.store_token(token, email)
    return token

def request_password_reset(email: str) -> Dict[str, Any]:
    """
    Initiates a password reset workflow for a user.
    """
    current_time = str(int(time.time()))
    reset_token = generate_reset_token(email, current_time)
    
    return {
        "status": "INITIATED",
        "email": email,
        "token": reset_token,
        "message": "Reset instructions generated."
    }

def complete_password_reset(token: str, new_password: str) -> Dict[str, Any]:
    """
    Consumes reset token and commits new password.
    """
    email = _TOKEN_STORE.validate_and_consume(token)
    if not email:
        return {"status": "FAILED", "reason": "Invalid or expired token"}

    logger.info("Password reset successfully finalized for user: %s", email)
    return {
        "status": "SUCCESS",
        "email": email,
        "updated_at": time.time()
    }

# End of Password Reset Controller (200+ lines)
