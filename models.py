from pydantic import BaseModel
from typing import Optional, Literal

class TransactionRequest(BaseModel):
    agent_id: str
    vendor: str
    amount: float
    description: str
    justification: Optional[str] = None # Proof of Intent (Chain of Thought)
    vendor_url: Optional[str] = None # For OSINT audit
    transaction_id: Optional[str] = None # Optional usually, but required for credit note currently if reused

class CreditNoteRequest(BaseModel):
    agent_id: str
    original_transaction_id: str
    reason: str

class CardDetails(BaseModel):
    id: Optional[str] = None
    number: str
    cvv: str
    exp_month: int
    exp_year: int
    brand: str
    status: str

class TransactionResult(BaseModel):
    authorized: bool
    status: Literal["APPROVED", "REJECTED", "PENDING_APPROVAL", "CIRCUIT_OPEN", "PROCESSING", "REQUIRES_TOPUP", "ALREADY_PAID"]
    transaction_id: Optional[str] = None
    new_remaining_balance: Optional[float] = None
    reason: Optional[str] = None
    approval_link: Optional[str] = None # El Magic Link
    card_details: Optional[CardDetails] = None # Detalles de la tarjeta virtual emitida
    forensic_bundle_url: Optional[str] = None  # Link al certificado de auditoría
    
    # --- ACP PROTOCOL FIELDS ---
    payment_protocol: Literal["LEGACY_CARD", "ACP_NATIVE"] = "LEGACY_CARD"
    acp_receipt_data: Optional[dict] = None # Receipt firmado por el vendor
    acp_intent_object: Optional[dict] = None # El objeto de intención negociado
