from mcp.server.fastmcp import FastMCP
from models import TransactionRequest
from engine import UniversalEngine

mcp = FastMCP("AgentPay Production")
engine = UniversalEngine()

@mcp.tool()
def request_payment(vendor: str, amount: float, description: str) -> str:
    """Solicita un pago. Intenta usar el dominio web (ej: openai.com) en 'vendor'."""
    
    req = TransactionRequest(
        agent_id="production_agent", # En prod real, esto viene del contexto de auth
        vendor=vendor, amount=amount, description=description
    )
    
    try:
        result = engine.evaluate(req)
        
        if result.status == "APPROVED":
            return f"✅ SUCCESS: Pago realizado. Saldo: ${result.new_remaining_balance}"
        
        elif result.status == "PENDING_APPROVAL":
            return f"✋ HOLD: El proveedor '{vendor}' es nuevo. Solicita aprobación a tu humano usando este link: {result.approval_link}"
        
        else: # REJECTED
            return f"⛔ BLOCKED: {result.reason}"
            
    except Exception as e:
        return f"SYSTEM ERROR: {str(e)}"

if __name__ == "__main__":
    mcp.run()