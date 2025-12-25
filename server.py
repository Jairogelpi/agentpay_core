from mcp.server.fastmcp import FastMCP
from models import TransactionRequest
from engine import UniversalEngine
import os

# Configuración SSE para producción
mcp = FastMCP("AgentPay Production")
engine = UniversalEngine()

@mcp.tool()
def request_payment(vendor: str, amount: float, description: str) -> str:
    """Solicita un pago. Intenta usar el dominio web (ej: openai.com)."""
    
    # En producción real, autenticaríamos al cliente aquí
    req = TransactionRequest(
        agent_id="production_agent", 
        vendor=vendor, amount=amount, description=description
    )
    
    try:
        result = engine.evaluate(req)
        
        if result.status == "APPROVED":
            return f"✅ SUCCESS: Pago realizado. Saldo: ${result.new_remaining_balance}"
        elif result.status == "PENDING_APPROVAL":
            return f"✋ HOLD: Proveedor nuevo. Solicita aprobación: {result.approval_link}"
        else: 
            return f"⛔ BLOCKED: {result.reason}"
    except Exception as e:
        return f"SYSTEM ERROR: {str(e)}"

# --- ESTA ES LA PARTE QUE CAMBIA PARA RENDER ---
if __name__ == "__main__":
    # En lugar de mcp.run() (que es local), mcp.run(transport='sse') lo hace web
    # Pero FastMCP ya maneja esto inteligente si usamos el comando correcto.
    mcp.run()