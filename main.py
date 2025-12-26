from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn
import os
import json
from engine import UniversalEngine
from models import TransactionRequest
from identity import IdentityManager

# Inicializamos
app = FastAPI(title="AgentPay Production Server")
engine = UniversalEngine()
identity_mgr = IdentityManager()

# --- RUTAS PÚBLICAS HTTP (HUMANOS & WEBHOOKS) ---

@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <html>
        <head><title>AgentPay Core</title></head>
        <body style="font-family: sans-serif; text-align: center; padding: 50px;">
            <h1>🛡️ AgentPay Active</h1>
            <p>Financial Security Infrastructure for AI Agents.</p>
            <p>System Status: 🟢 ONLINE</p>
        </body>
    </html>
    """

@app.post("/webhook")
async def stripe_webhook(request: Request):
    """Endpoint para recibir notificaciones de Stripe (Top-Ups)"""
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    
    try:
        # Pasamos el raw body al engine
        result = engine.process_stripe_webhook(payload, sig_header)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/admin/approve", response_class=HTMLResponse)
async def approve_endpoint(token: str):
    """El Magic Link que pulsa el humano para aprobar"""
    result = engine.process_approval(token)
    
    color = "green" if result.get("status") == "APPROVED" else "red"
    return f"""
    <html>
        <body style="font-family: sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: {color}">{result.get("status")}</h1>
            <p>{result.get("message")}</p>
            <p>Reference: {result.get("transaction_id", "N/A")}</p>
        </body>
    </html>
    """

# --- RUTAS API (PARA LOS AGENTES / MCP) ---
# En un despliegue real FastAPI, exponemos las tools como endpoints REST
# para que LangChain/crews puedan llamarlos vía HTTP Request.

@app.post("/v1/pay")
async def pay(req: dict):
    """Endpoint principal para que los agentes pidan dinero"""
    # { "agent_id": "...", "vendor": "...", "amount": 10.0, "description": "..." }
    real_req = TransactionRequest(**req)
    res = engine.evaluate(real_req)
    return {
        "success": res.authorized,
        "status": res.status,
        "message": res.reason,
        "balance": res.new_remaining_balance,
        "approval_link": res.approval_link
    }

@app.post("/v1/identity/create")
async def create_id(req: dict):
    return identity_mgr.create_identity(req.get("agent_id"))

@app.get("/v1/identity/{identity_id}/check")
async def check_id(identity_id: str):
    return identity_mgr.check_inbox(identity_id)

@app.post("/v1/topup/create")
async def create_topup_link(req: dict):
    url = engine.create_topup_link(req.get("agent_id"), req.get("amount"))
    return {"url": url}

@app.post("/v1/identity/proxy")
async def get_proxy(req: dict):
    """Obtiene una IP residencial para evitar bloqueos"""
    return identity_mgr.get_residential_proxy(req.get("region", "US"))

@app.post("/v1/identity/captcha")
async def solve_captcha(req: dict):
    """Resuelve un captcha visual"""
    return identity_mgr.solve_captcha(req.get("image_url"))

if __name__ == "__main__":
    # Para correr local: python main.py
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)