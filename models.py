from pydantic import BaseModel
from typing import Optional, Literal

class TransactionRequest(BaseModel):
    agent_id: str
    vendor: str
    amount: float
    description: str

class TransactionResult(BaseModel):
    authorized: bool
    # Aquí está la clave del 100% de cobertura: PENDING_APPROVAL
    status: Literal["APPROVED", "REJECTED", "PENDING_APPROVAL"]
    transaction_id: Optional[str] = None
    new_remaining_balance: Optional[float] = None
    reason: Optional[str] = None
    approval_link: Optional[str] = None # El Magic Link