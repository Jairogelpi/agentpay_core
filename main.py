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
    Recibe correos de Brevo y los guarda en SQL. Adaptado al payload Real de Brevo.
    Resuelve el agent_id completo consultando la tabla identities.
    """
    try:
        data = await request.json()
        
        items = data.get("items", [])
        if not items:
            print("📩 Webhook hit: No items in payload (Test/Ping)")
            return {"status": "ok", "message": "no items"}

        for item in items:
            sender_obj = item.get("From", {})
            sender = sender_obj.get("Address", "")
            
            to_list = item.get("To", [])
            recipient = to_list[0].get("Address", "") if to_list else ""
            
            subject = item.get("Subject", "")
            body = item.get("RawTextBody") or item.get("ExtractedMarkdownMessage", "")

            print(f"📩 Webhook item: From={sender}, To={recipient}, Sub={subject}")
            
            if not recipient:
                continue

            # 1. Intentar buscar el agent_id REAL (completo) en la tabla identities
            real_agent_id = None
            try:
                # Buscamos por email exacto
                id_lookup = engine.db.table("identities").select("agent_id").eq("email", recipient).execute()
                if id_lookup.data:
                    real_agent_id = id_lookup.data[0].get("agent_id")
                    print(f"🔍 Resolved full agent_id: {real_agent_id}")
            except Exception as lookup_err:
                print(f"⚠️ Error lookup agent_id: {lookup_err}")

            # 2. Fallback a extracción manual si la DB no tiene el registro o falla
            if not real_agent_id:
                user_part = recipient.split("@")[0]
                extracted = user_part.replace("agent-", "").replace("bot_", "").replace("sk_", "")
                real_agent_id = f"sk_{extracted}" # Esto será el ID truncado (8 chars)
                print(f"⚠️ Using truncated fallback agent_id: {real_agent_id}")

            try:
                engine.db.table("inbound_emails").insert({
                    "agent_id": real_agent_id,
                    "sender": sender,
                    "recipient": recipient,
                    "subject": subject,
                    "body_text": body
                }).execute()
                print(f"✅ Ingested email for {real_agent_id}")
            except Exception as db_err:
                print(f"⚠️ Error guardando email: {db_err}")
        
        return {"status": "ok"}
    except Exception as e:
        print(f"❌ Webhook Global Error: {e}")
        return {"status": "error", "message": str(e)}


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

@app.post("/v1/legal/passport")
async def get_passport(req: dict):
    """KYC: Emite Pasaporte Digital para User-Agent"""
    return engine.get_agent_passport(req.get("agent_id"))

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

@app.post("/v1/insurance/configure")
async def config_insurance(req: dict):
    """Activa/Desactiva el Seguro Antialucinaciones"""
    return engine.configure_insurance(req.get("agent_id"), req.get("enabled"), req.get("strictness", "HIGH"))

@app.post("/v1/market/procure")
async def market_procure(req: dict):
    """Agencia de Compras: Ejecución estricta B2B con OSINT check"""
    return engine.process_procurement(
        req.get("agent_id"), 
        req.get("vendor"), 
        float(req.get("amount", 0)), 
        req.get("items", []),
        req.get("description", "B2B Order")
    )

@app.post("/v1/transactions/dispute")
async def dispute_tx(req: dict):
    return engine.dispute_transaction(req.get("agent_id"), req.get("transaction_id"), req.get("reason"))

@app.post("/v1/trust/verify")
async def trust_verify(req: dict):
    """Verificación Proactiva de Servicio (Auto-Dispute)"""
    return engine.verify_service_delivery(req.get("agent_id"), req.get("transaction_id"), req.get("service_logs"))

# --- AUTONOMOUS ESCROW API ---
@app.post("/v1/escrow/create")
async def escrow_create(req: dict):
    return engine.create_escrow_transaction(req.get("agent_id"), req.get("vendor"), float(req.get("amount")), req.get("description"))

@app.post("/v1/escrow/confirm")
async def escrow_confirm(req: dict):
    return engine.confirm_delivery(req.get("agent_id"), req.get("transaction_id"))

@app.post("/v1/escrow/dispute")
async def escrow_dispute(req: dict):
    """El Juez IA entra en acción"""
    return engine.raise_escrow_dispute(
        req.get("agent_id"), 
        req.get("transaction_id"), 
        req.get("issue_description"), 
        req.get("technical_evidence")
    )

@app.post("/v1/legal/sign_tos")
async def legal_sign_tos(req: dict):
    """Firma de TyC con Certificado de Responsabilidad"""
    return engine.sign_terms_of_service(req.get("agent_id"), req.get("platform_url"))

# --- M2M MARKET API ---
@app.post("/v1/market/quote")
async def market_quote(req: dict):
    """Solicitar cotización a otro agente (M2M)"""
    return engine.process_quote_request(req.get("provider_id"), req.get("service_type"), req.get("params", {}))

@app.post("/v1/market/directory")
async def market_directory(req: dict):
    """Buscar agentes por Rol y Reputación"""
    return engine.get_service_directory(req.get("role", "ALL"))

# --- ROI ANALYTICS API ---
@app.post("/v1/analytics/report_value")
async def report_value(req: dict):
    """Reportar valor generado por una transacción (ROI)"""
    return engine.report_value(req.get("agent_id"), req.get("transaction_id"), float(req.get("perceived_value", 0.0)))

@app.get("/v1/analytics/dashboard/{agent_id}")
async def analytics_dashboard(agent_id: str):
    """Dashboard de Observabilidad (ROI, Salud Financiera)"""
    return engine.get_dashboard_metrics(agent_id)

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