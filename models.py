from pydantic import BaseModel
from typing import Optional, Literal

class TransactionRequest(BaseModel):
    agent_id: str
    vendor: str
    amount: float
    description: str
    justification: Optional[str] = None # Proof of Intent (Chain of Thought)
    vendor_url: Optional[str] = None # For OSINT audit

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
    status: Literal["APPROVED", "REJECTED", "PENDING_APPROVAL", "CIRCUIT_OPEN"]
    transaction_id: Optional[str] = None
    new_remaining_balance: Optional[float] = None
    reason: Optional[str] = None
    approval_link: Optional[str] = None # El Magic Link
    card_details: Optional[CardDetails] = None # Detalles de la tarjeta virtual emitida
    forensic_bundle_url: Optional[str] = None  # Link al certificado de auditoría