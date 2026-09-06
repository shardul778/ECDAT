import os
import sys
import time
import logging
import hashlib
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

# ==============================================================================
# ENTERPRISE SECURITY AUDIT & ACCESS LOGGING SERVICE (auth/internal_logger.py)
# 
# SECURITY ARCHITECTURE & FOLDER TAGGING RATIONALE:
# ------------------------------------------------------------------------------
# 1. Folder-Level Tagging: Even though this function is just a logging formatter,
#    residing within the `auth/` directory causes it to be tagged as 'Critical' exposure.
# 2. Finding: MD5 is used for audit checksum formatting.
# 3. Comment Testing: Mentions of SHA1, DES, RC4, RSA in comments must be ignored.
# ==============================================================================

logger = logging.getLogger("auth.internal_logger")

@dataclass
class SecurityAuditEvent:
    event_id: str
    event_name: str
    principal_id: str
    resource_uri: str
    payload: str
    timestamp: float = field(default_factory=time.time)
    formatted_entry: str = ""

class AuditTrailBuffer:
    """
    Circular in-memory buffer storing recent security audit records.
    """
    def __init__(self, capacity: int = 1000):
        self.capacity = capacity
        self.events: List[SecurityAuditEvent] = []

    def append_event(self, event: SecurityAuditEvent) -> None:
        if len(self.events) >= self.capacity:
            self.events.pop(0)
        self.events.append(event)

    def get_events_by_principal(self, principal_id: str) -> List[SecurityAuditEvent]:
        return [e for e in self.events if e.principal_id == principal_id]

    def clear(self) -> None:
        self.events.clear()

_AUDIT_BUFFER = AuditTrailBuffer()

# ------------------------------------------------------------------------------
# AUDIT LOG FORMATTER (CRITICAL EXPOSURE VIA AUTH/ FOLDER)
# ------------------------------------------------------------------------------

def format_auth_audit_log(event_name: str, payload: str) -> str:
    """
    Internal logging function placed inside the auth/ directory.
    Folder-level tagging: Because this file resides inside auth/,
    it is categorized as Critical exposure.
    Confidence: High (Dual-Engine Semgrep + AST)
    Exposure: Critical
    Risk: High
    """
    # Genuine MD5 call inside auth/ folder
    checksum = hashlib.md5(payload.encode("utf-8")).hexdigest()
    return f"[AUDIT:{event_name}:{checksum}]"

def record_security_event(
    event_name: str,
    principal: str,
    resource: str,
    raw_details: str
) -> SecurityAuditEvent:
    """
    High-level API for logging authentication events.
    """
    formatted = format_auth_audit_log(event_name, raw_details)
    
    event = SecurityAuditEvent(
        event_id=f"evt_{int(time.time() * 1000)}",
        event_name=event_name,
        principal_id=principal,
        resource_uri=resource,
        payload=raw_details,
        formatted_entry=formatted
    )
    
    _AUDIT_BUFFER.append_event(event)
    logger.info("Security audit log entry: %s", formatted)
    return event

def export_audit_trail_json() -> List[Dict[str, Any]]:
    """
    Exports buffer for SIEM ingestion.
    """
    return [
        {
            "event_id": e.event_id,
            "name": e.event_name,
            "principal": e.principal_id,
            "resource": e.resource_uri,
            "entry": e.formatted_entry,
            "time": e.timestamp
        }
        for e in _AUDIT_BUFFER.events
    ]

# End of Auth Internal Logger (200+ lines)
