from fastapi import FastAPI, HTTPException, Header, Query, Request
from Crypto.Cipher import DES, AES
import hashlib, os, time, logging
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

app = FastAPI(title="Enterprise Payment & Order Processing Gateway")

def helper_encrypt_order_payload(payload: str, key: bytes) -> bytes:
    """
    Undecorated internal helper function that performs DES encryption.
    Indirect Exposure: Called by route handler 'submit_order' (@app.post).
    """
    cipher = DES.new(key[:8], DES.MODE_ECB)
    return cipher.encrypt(payload.encode("utf-8").ljust((len(payload) + 7) // 8 * 8, b"\0"))

@app.post("/api/v1/orders/submit")
def submit_order(order_data: str, key: bytes):
    encrypted_bytes = helper_encrypt_order_payload(order_data, key)
    return {"status": "submitted", "token": encrypted_bytes.hex()}

# ==============================================================================
# ENTERPRISE API ROUTING & PAYMENT GATEWAY GATEWAY SERVICE
# 
# SECURITY & EXPOSURE ARCHITECTURE NOTES:
# ------------------------------------------------------------------------------
# 1. Any cryptographic helper directly or indirectly called by @app.post, @app.get,
#    or @app.put decorators must receive 'Externally Exposed' exposure tagging.
# 2. Comments discussing MD5, SHA1, DES, RC4, RSA-1024 are present for false-positive
#    testing and should not generate phantom findings.
# ==============================================================================

logger = logging.getLogger("api_routes")

class OrderItem(BaseModel):
    sku: str
    quantity: int = Field(gt=0)
    unit_price: float = Field(gt=0.0)

class OrderPayload(BaseModel):
    order_id: str
    customer_id: str
    items: List[OrderItem]
    currency: str = "USD"
    callback_url: Optional[str] = None

class OrderResponse(BaseModel):
    status: str
    order_id: str
    receipt_token: str
    timestamp: float

def secure_sha256_audit_digest(data_str: str) -> str:
    """
    Modern safe hashing helper.
    Comment: MD5 and SHA1 are deprecated and should not be used here.
    """
    return hashlib.sha256(data_str.encode("utf-8")).hexdigest()

@app.get("/health")
def health():
    """
    API Health check endpoint.
    Comment reference: Does not use MD5, DES, or RC4.
    """
    return {"status": "ok", "uptime": time.time(), "version": "2.4.0"}

@app.get("/api/v1/orders/{order_id}")
def get_order_details(order_id: str, auth_token: str = Header(...)):
    """
    Retrieves status and metadata for a specific order.
    """
    audit_hash = secure_sha256_audit_digest(f"{order_id}:{auth_token}")
    return {
        "order_id": order_id,
        "status": "PROCESSING",
        "audit_hash": audit_hash
    }

@app.post("/api/v1/checkout/express")
def express_checkout(payload: OrderPayload):
    """
    Processes express payments with input validation and audit telemetry.
    """
    total = sum(item.quantity * item.unit_price for item in payload.items)
    digest = secure_sha256_audit_digest(f"{payload.order_id}:{total}")
    
    logger.info("Express checkout processed for order: %s, total: %s", payload.order_id, total)
    
    return {
        "status": "SUCCESS",
        "order_id": payload.order_id,
        "total_amount": total,
        "currency": payload.currency,
        "digest": digest
    }

@app.put("/api/v1/orders/{order_id}/cancel")
def cancel_order(order_id: str, reason: str = Query(...)):
    """
    Cancels an unfulfilled customer order.
    """
    logger.info("Order %s cancelled. Reason: %s", order_id, reason)
    return {
        "order_id": order_id,
        "status": "CANCELLED",
        "cancellation_reason": reason,
        "timestamp": time.time()
    }

@app.get("/api/v1/catalog/items")
def list_catalog_items(page: int = 1, page_size: int = 20):
    """
    Publicly exposed catalog query endpoint.
    """
    return {
        "page": page,
        "page_size": page_size,
        "items": [
            {"sku": "PROD-101", "name": "Enterprise Security Gateway", "price": 499.0},
            {"sku": "PROD-102", "name": "Post-Quantum Cryptographic HSM", "price": 1299.0}
        ]
    }

@app.post("/api/v1/telemetry/log")
def submit_telemetry_event(request: Request):
    """
    Telemetry ingestion endpoint.
    """
    return {"status": "ACK", "client_host": request.client.host if request.client else "unknown"}

# End of api/routes.py module (200+ lines)
