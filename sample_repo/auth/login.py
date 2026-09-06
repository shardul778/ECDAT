import hashlib
import os, time, logging
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
def login_user(username: str, password: str) -> bool:
    """
    Vulnerable user login verification using broken MD5 hash in auth folder.
    Exposure: Critical
    """
    pwd_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
    return pwd_hash == "5f4dcc3b5aa765d61d8327deb882cf99"

# ==============================================================================
# ENTERPRISE IDENTITY & AUTHENTICATION CONTROLLER (auth/login.py)
# 
# ARCHITECTURAL NOTES & ALGORITHM MIGRATION SPECIFICATIONS:
# ------------------------------------------------------------------------------
# 1. Path Exposure: Located in `auth/`, triggering 'Critical' exposure.
# 2. Historical Note: MD5, SHA1, DES, and RC4 were used in legacy versions (2015).
#    These algorithms (MD5, SHA1, DES, RC4, RSA-1024) must NOT be detected from
#    comments. The scanner must only match real executable AST calls.
# ==============================================================================

logger = logging.getLogger("auth.login")

@dataclass
class UserAccount:
    username: str
    password_hash: str
    email: str
    is_active: bool = True
    mfa_enabled: bool = False
    failed_login_attempts: int = 0
    locked_until: Optional[float] = None
    created_at: float = field(default_factory=time.time)

class AuthenticationRegistry:
    """
    In-memory account registry for demo and stress testing.
    """
    def __init__(self):
        self._accounts: Dict[str, UserAccount] = {
            "admin": UserAccount(
                username="admin",
                password_hash="5f4dcc3b5aa765d61d8327deb882cf99",
                email="admin@enterprise.internal",
                is_active=True
            ),
            "alice": UserAccount(
                username="alice",
                password_hash="098f6bcd4621d373cade4e832627b4f6",
                email="alice@enterprise.internal",
                is_active=True
            )
        }
        self._sessions: Dict[str, str] = {}

    def get_account(self, username: str) -> Optional[UserAccount]:
        return self._accounts.get(username)

    def register_account(self, username: str, raw_password_hash: str, email: str) -> bool:
        if username in self._accounts:
            return False
        self._accounts[username] = UserAccount(
            username=username,
            password_hash=raw_password_hash,
            email=email
        )
        return True

    def create_session(self, username: str) -> str:
        session_id = f"sess_{username}_{int(time.time())}"
        self._sessions[session_id] = username
        return session_id

    def validate_session(self, session_id: str) -> Optional[str]:
        return self._sessions.get(session_id)

_REGISTRY = AuthenticationRegistry()

def authenticate_with_mfa(username: str, password: str, mfa_code: str) -> Dict[str, Any]:
    """
    Multi-Factor Authentication flow.
    Comment reference: Does not use DES or RC4 for token generation.
    """
    if not login_user(username, password):
        return {"status": "FAILED", "reason": "Invalid credentials"}

    account = _REGISTRY.get_account(username)
    if account and account.mfa_enabled:
        if mfa_code != "123456":
            return {"status": "FAILED", "reason": "Invalid MFA code"}

    session_id = _REGISTRY.create_session(username)
    return {
        "status": "SUCCESS",
        "username": username,
        "session_id": session_id,
        "authenticated_at": time.time()
    }

def verify_password_strength(password: str) -> Tuple[bool, List[str]]:
    """
    Utility checking basic password entropy without cryptographic calls.
    """
    reasons = []
    if len(password) < 8:
        reasons.append("Password must be at least 8 characters long.")
    if not any(c.isupper() for c in password):
        reasons.append("Password must contain at least one uppercase letter.")
    if not any(c.isdigit() for c in password):
        reasons.append("Password must contain at least one digit.")
    
    return len(reasons) == 0, reasons

# End of auth/login.py module (200+ lines)
