from mcp.server.fastmcp import FastMCP
from models import TransactionRequest
from engine import UniversalEngine
import os

# Configuración SSE para producción
mcp = FastMCP("AgentPay Production")
engine = UniversalEngine()

import json

@mcp.tool()
def request_payment(vendor: str, amount: float, description: str, agent_id: str = "production_agent") -> str:
    """Solicita un pago. Intenta usar el dominio web (ej: openai.com). Devuelve JSON."""
    
    req = TransactionRequest(
        agent_id=agent_id, 
        vendor=vendor, amount=amount, description=description
    )
    
    try:
        result = engine.evaluate(req)
        output = {
            "success": result.authorized,
            "status": result.status,
            "message": result.reason,
            "balance": result.new_remaining_balance,
            "approval_link": result.approval_link
        }
        return json.dumps(output)
    except Exception as e:
        return json.dumps({"success": False, "status": "ERROR", "message": str(e)})

@mcp.tool()
def report_fraud(vendor: str, reason: str, agent_id: str = "production_agent") -> str:
    """Reporta un fraude a la Colmena Global."""
    try:
        res = engine.report_fraud(agent_id, vendor, reason)
        return json.dumps(res)
    except Exception as e:
        return json.dumps({"success": False, "message": str(e)})

@mcp.tool()
def approve_payment(token: str) -> str:
    """Aprueba manualmente un pago pendiente usando el token del Magic Link."""
    try:
        res = engine.process_approval(token)
        return json.dumps(res)
    except Exception as e:
        return json.dumps({"status": "ERROR", "message": str(e)})

# --- IDENTITY AS A SERVICE (PROTOCOL GHOST) ---
from identity import IdentityManager
identity_mgr = IdentityManager()

@mcp.tool()
def create_identity(agent_id: str) -> str:
    """Genera una identidad digital (email) para saltar verificaciones."""
    try:
        res = identity_mgr.create_identity(agent_id)
        return json.dumps(res)
    except Exception as e:
        return json.dumps({"status": "ERROR", "message": str(e)})

@mcp.tool()
def check_inbox(identity_id: str) -> str:
    """Revisa el buzón temporal y extrae códigos OTP con IA."""
    try:
        res = identity_mgr.check_inbox(identity_id)
        return json.dumps(res)
    except Exception as e:
        return json.dumps({"status": "ERROR", "message": str(e)})

@mcp.tool()
def create_topup(agent_id: str, amount: float) -> str:
    """Genera un link de pago para recargar saldo en la billetera del agente."""
    try:
        url = engine.create_topup_link(agent_id, amount)
        return json.dumps({"url": url})
    except Exception as e:
        return json.dumps({"status": "ERROR", "message": str(e)})

@mcp.tool()
def get_proxy(region: str = "US") -> str:
    """Obtiene una configuración de Proxy Residencial para evitar bloqueos."""
    try:
        res = identity_mgr.get_residential_proxy(region)
        return json.dumps(res)
    except Exception as e:
        return json.dumps({"status": "ERROR", "message": str(e)})

@mcp.tool()
def solve_captcha(image_url: str) -> str:
    """Resuelve un captcha visual usando IA."""
    try:
        res = identity_mgr.solve_captcha(image_url)
        return json.dumps(res)
    except Exception as e:
        return json.dumps({"status": "ERROR", "message": str(e)})


# --- GOVERNANCE OS TOOLS ---

@mcp.tool()
def get_status(agent_id: str) -> str:
    """[GOVERNANCE] Check financial health, credit score, and balance."""
    try:
        res = engine.get_agent_status(agent_id)
        return json.dumps(res)
    except Exception as e:
        return json.dumps({"status": "ERROR", "message": str(e)})

@mcp.tool()
def get_dashboard(agent_id: str) -> str:
    """[GOVERNANCE] CFO Dashboard: View ROI, Total Spend, and Value Generated."""
    try:
        res = engine.get_dashboard_metrics(agent_id)
        return json.dumps(res)
    except Exception as e:
        return json.dumps({"status": "ERROR", "message": str(e)})

@mcp.tool()
def sign_tos(agent_id: str, platform_url: str, forensic_hash: str = "N/A") -> str:
    """[LEGAL] Sign Terms of Service with Liability Certificate and Intent Hash."""
    try:
        res = engine.sign_terms_of_service(agent_id, platform_url, forensic_hash)
        return json.dumps(res)
    except Exception as e:
        return json.dumps({"status": "ERROR", "message": str(e)})

@mcp.tool()
def verify_service(agent_id: str, transaction_id: str, logs: str) -> str:
    """[TRUST] Report service failure (e.g. 500 Error). Triggers Auto-Dispute if valid."""
    try:
        res = engine.verify_service_delivery(agent_id, transaction_id, logs)
        return json.dumps(res)
    except Exception as e:
        return json.dumps({"status": "ERROR", "message": str(e)})

@mcp.tool()
def market_directory(role: str = None) -> str:
    """[M2M] Find other agents to hire based on Reputation Score."""
    try:
        res = engine.get_service_directory(role)
        return json.dumps(res)
    except Exception as e:
        return json.dumps({"status": "ERROR", "message": str(e)})

# --- ESTA ES LA PARTE QUE CAMBIA PARA RENDER ---
if __name__ == "__main__":
    # En despliegues como Render, FastMCP puede funcionar en modo SSE 
    # si se lanza con el comando adecuado, pero 'main.py' es el servidor recomendado.
    # Aquí mantenemos la compatibilidad básica.
    mcp.run()