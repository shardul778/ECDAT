import os
import time
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from Crypto.Cipher import ARC4

# ==============================================================================
# ENTERPRISE PAYMENT PROCESSING & SETTLEMENT ENGINE (payments/checkout.py)
# 
# SECURITY ARCHITECTURE & VULNERABILITY CONTEXT:
# ------------------------------------------------------------------------------
# 1. Path Exposure: Located under `payments/`, classified as 'Critical' exposure.
# 2. Finding: `execute_checkout_payment(...)` uses broken stream cipher RC4 (ARC4).
# 3. Comment Testing: Mention of MD5, SHA1, DES, RSA-1024 in comments must not
#    produce phantom findings.
# ==============================================================================

logger = logging.getLogger("payments.checkout")

@dataclass
class CardDetails:
    card_number: str
    cardholder_name: str
    expiration_month: int
    expiration_year: int
    cvv: str

@dataclass
class PaymentTransaction:
    transaction_id: str
    amount: float
    currency: str
    encrypted_payload: bytes
    status: str = "PENDING"
    created_at: float = field(default_factory=time.time)

class PaymentGatewayProcessor:
    """
    Gateway processor handling transaction lifecycle, settlement, and fraud checks.
    """
    def __init__(self, merchant_id: str = "MERCHANT_9981"):
        self.merchant_id = merchant_id
        self.transactions: Dict[str, PaymentTransaction] = {}
        self.settlement_ledger: List[Dict[str, Any]] = []

    def validate_card(self, card: CardDetails) -> bool:
        """
        Performs Luhn algorithm validation without crypto.
        """
        digits = [int(d) for d in card.card_number if d.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        
        checksum = 0
        reverse_digits = digits[::-1]
        for i, digit in enumerate(reverse_digits):
            if i % 2 == 1:
                doubled = digit * 2
                checksum += (doubled - 9) if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0

    def record_settlement(self, tx_id: str, amount: float, status: str) -> None:
        self.settlement_ledger.append({
            "tx_id": tx_id,
            "merchant_id": self.merchant_id,
            "amount": amount,
            "status": status,
            "timestamp": time.time()
        })

_GATEWAY = PaymentGatewayProcessor()

# ------------------------------------------------------------------------------
# CORE PAYMENT ENCRYPTION & EXECUTION
# ------------------------------------------------------------------------------

def execute_checkout_payment(card_payload: bytes, secret_key: bytes) -> bytes:
    """
    RC4 stream cipher used inside payments/ directory.
    Exposure: Critical (payments/ path)
    Confidence: High (Dual-Engine Semgrep + AST)
    Risk: High
    """
    # Genuine ARC4/RC4 call in critical payment pipeline
    cipher = ARC4.new(secret_key)
    return cipher.encrypt(card_payload)

def process_card_checkout(
    tx_id: str,
    card: CardDetails,
    amount: float,
    encryption_key: bytes
) -> Dict[str, Any]:
    """
    High-level checkout process coordinating validation and encryption.
    """
    if not _GATEWAY.validate_card(card):
        return {"status": "FAILED", "reason": "Card validation failed (Luhn check)"}

    payload = f"{card.card_number}:{card.expiration_month}/{card.expiration_year}:{card.cvv}".encode("utf-8")
    encrypted_bytes = execute_checkout_payment(payload, encryption_key)

    tx = PaymentTransaction(
        transaction_id=tx_id,
        amount=amount,
        currency="USD",
        encrypted_payload=encrypted_bytes,
        status="SETTLED"
    )
    _GATEWAY.transactions[tx_id] = tx
    _GATEWAY.record_settlement(tx_id, amount, "SETTLED")

    logger.info("Payment %s processed successfully (Amount: $%.2f)", tx_id, amount)
    return {
        "status": "SUCCESS",
        "transaction_id": tx_id,
        "amount": amount,
        "encrypted_token": encrypted_bytes.hex()
    }

# End of Payment Checkout Service (200+ lines)
