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
identity_mgr = IdentityManager(engine.db)

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

@app.post("/v1/identity/webhook")
async def brevo_inbound_webhook(request: Request):
    """
    Recibe correos de Brevo y los guarda en SQL. Robust extractor.
    """
    try:
        data = await request.json()
        recipient = data.get("Recipient", "")
        sender = data.get("Sender", "")
        subject = data.get("Subject", "")
        
        print(f"📩 Webhook hit: From={sender}, To={recipient}, Sub={subject}")
        
        # Extracción agresiva del agent_id del destinatario
        # Formatos: agent-sk_123...@... , bot_sk_123...@... , sk_123...@...
        user_part = recipient.split("@")[0]
        agent_id = user_part.replace("agent-", "").replace("bot_", "")
        
        # Si por alguna razón el agent_id está vacío o no empieza con sk_, intentar buscarlo en la DB
        # pero para el flujo Ghost V2 confiamos en el destinatario.
        
        engine.db.table("inbound_emails").insert({
            "agent_id": agent_id,
            "sender": sender,
            "recipient": recipient,
            "subject": subject,
            "body_text": data.get("TextBody", "")
        }).execute()

        print(f"✅ Ingested email for agent: {agent_id}")
        return {"status": "ok", "agent_id": agent_id}
        
    except Exception as e:
        print(f"❌ Webhook Error: {str(e)}")
        return JSONResponse(status_code=400, content={"error": str(e)})

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
    return identity_mgr.create_identity(req.get("agent_id"), req.get("needs_phone", False))

@app.get("/v1/identity/{identity_id}/check")
async def check_id(identity_id: str):
    return identity_mgr.check_inbox(identity_id)

@app.post("/v1/identity/update_session")
async def update_session(req: dict):
    """Guarda estado/cookies de la identidad"""
    return identity_mgr.update_session_data(req.get("identity_id"), req.get("session_data"))

@app.get("/v1/identity/{identity_id}/sms")
async def check_sms(identity_id: str):
    return identity_mgr.check_sms_inbox(identity_id)

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

# --- VISION 2.0 ENDPOINTS ---
from legal import LegalWrapper
from streaming import StreamingMoney

legal_wrapper = LegalWrapper()
streaming_money = StreamingMoney(engine.db)

@app.post("/v1/credit/score")
async def get_credit_score(req: dict):
    """Consulta el Bureau de Crédito de IA"""
    return engine.credit_bureau.check_credit_eligibility(req.get("agent_id"))

@app.post("/v1/legal/sign")
async def sign_contract(req: dict):
    """Wrapper Legal: Firma contratos en nombre del agente"""
    return legal_wrapper.sign_contract(req.get("agent_id"), req.get("contract_hash"))

@app.post("/v1/streaming/pack")
async def stream_payment(req: dict):
    """Streaming Money: Micropagos de alta frecuencia"""
    return streaming_money.stream_packet(req.get("agent_id"), req.get("vendor"), float(req.get("amount", 0)))

@app.post("/v1/fraud/report")
async def report_fraud(req: dict):
    """Mente Colmena: Reportar un fraude a la comunidad"""
    return engine.report_fraud(req.get("agent_id"), req.get("vendor"), req.get("reason"))

@app.post("/v1/agent/settings")
async def update_settings(req: dict):
    """Configura Webhook y Email de contacto del agente"""
    return engine.update_agent_settings(req.get("agent_id"), req.get("webhook_url"), req.get("owner_email"))

@app.post("/v1/agent/status")
async def agent_status(req: dict):
    """Panel de Control: Saldo, Crédito y Configuración"""
    return engine.get_agent_status(req.get("agent_id"))

# --- PROFESSIONAL SDK ENDPOINTS ---

@app.post("/v1/transactions/status")
async def check_tx_status(req: dict):
    return engine.check_payment_status(req.get("transaction_id"))

@app.post("/v1/invoices/download")
async def download_invoice(req: dict):
    return engine.get_invoice_url(req.get("transaction_id"))

@app.post("/v1/agent/register")
async def register_agent(req: dict):
    return engine.register_new_agent(req.get("client_name"))

@app.post("/v1/agent/limits")
async def update_limits(req: dict):
    return engine.update_limits(req.get("agent_id"), req.get("max_tx"), req.get("daily_limit"))

@app.post("/v1/agent/notify")
async def agent_notify(req: dict):
    return engine.send_alert(req.get("agent_id"), req.get("message"))

@app.post("/v1/transactions/dispute")
async def dispute_tx(req: dict):
    return engine.dispute_transaction(req.get("agent_id"), req.get("transaction_id"), req.get("reason"))

@app.post("/v1/transactions/approve")
async def approve_tx(req: dict):
    return engine.process_approval(req.get("token"))

@app.post("/v1/identity/list")
async def list_identities(req: dict):
    return identity_mgr.get_active_identities(req.get("agent_id"))

if __name__ == "__main__":
    # Para correr local: python main.py
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)