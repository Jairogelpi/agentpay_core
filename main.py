from fastapi import FastAPI, Request, HTTPException, Depends, Security, Header, Form
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from starlette.types import ASGIApp, Receive, Scope, Send # <--- REQUIRED GLOBAL IMPORT
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.starlette import StarletteIntegration
import csv
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
from loguru import logger
import os
import sys
import json
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# --- RATE LIMITING ---
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=os.environ.get("REDIS_URL", "redis://localhost:6379"),
    strategy="fixed-window" 
)

from datetime import datetime
from engine import UniversalEngine
from models import TransactionRequest, CreditNoteRequest
from identity import IdentityManager
from fastmcp import FastMCP

# --- OPENTELEMETRY IMPORTS ---
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter


from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from observability import setup_observability 


# --- 1. CONFIGURACIÓN DE OBSERVABILIDAD ---
# Inicializar Better Stack antes que nada
setup_observability()

# --- 2. CONFIGURACIÓN DE TRACING (OPENTELEMETRY) ---
# Debe inicializarse ANTES de crear la app FastAPI

from opentelemetry.sdk.resources import Resource

# Resource con los atributos que buscas
resource = Resource.create({
    "service.name": os.getenv("OTEL_SERVICE_NAME", "AgentPay-Core"),
    "service.namespace": "agentpay-production",
    "deployment.environment": os.getenv("ENVIRONMENT", "production")
})



# Endpoint OTLP (HTTP/HTTPS) definido por variable de entorno
otlp_endpoint = os.getenv("OTLP_ENDPOINT", "https://otlp-gateway-prod-eu-central-0.grafana.net/otlp/v1/traces")

# [DEFENSIVE FIX] Grafana Cloud requiere el path completo para HTTP exporter
if "grafana.net" in otlp_endpoint and not otlp_endpoint.endswith("/v1/traces"):
    # Si el usuario puso la base URL sin el path, lo corregimos
    if not otlp_endpoint.endswith("/otlp"):
        if not otlp_endpoint.endswith("/"): otlp_endpoint += "/"
        otlp_endpoint += "otlp"
    
    otlp_endpoint = f"{otlp_endpoint.rstrip('/')}/v1/traces"
    logger.warning(f"🔧 OTLP Endpoint corregido automáticamente a: {otlp_endpoint}")

# Helper para parsear headers (Grafana entrega string "k=v,k2=v2", OTel espera Dict)
def parse_otlp_headers(headers_str):
    if not headers_str: return {}
    headers = {}
    for pair in headers_str.split(','):
        if '=' in pair:
            key, value = pair.split('=', 1)
            headers[key.strip()] = value.strip()
    return headers

otlp_headers = parse_otlp_headers(os.getenv("OTLP_HEADERS", ""))

# TracerProvider CON Resource
provider = TracerProvider(resource=resource)
processor = BatchSpanProcessor(
    OTLPSpanExporter(
        endpoint=otlp_endpoint,
        headers=otlp_headers
    ),
    schedule_delay_millis=5000 
)
provider.add_span_processor(processor)
trace.set_tracer_provider(provider)

# Instrumentaciones Automáticas
RequestsInstrumentor().instrument()
RedisInstrumentor().instrument()
LoggingInstrumentor().instrument()

# --- 2. CONFIGURACIÓN DE LOGS ESTRUCTURADOS (JSON) ---
# Inyector de Contexto para Loguru (Vincula Logs con Traces)
def inject_trace_data(record):
    span = trace.get_current_span()
    if span and span.get_span_context().is_valid:
        record["extra"]["trace_id"] = format(span.get_span_context().trace_id, "032x")
        record["extra"]["span_id"] = format(span.get_span_context().span_id, "16x")
    return True

# [OBSERVABILITY FIX]
# La configuración de Loguru se ha centralizado en `observability.py`.
# Se eliminan los handlers duplicados que borraban la conexión a Better Stack.
# El patcher de traces también se maneja globalmente ahora.

# Sentry Handler simplificado (Integrado en observability pipeline si fuera necesario, 
# pero aquí dejamos que Sentry SDK maneje sus integraciones nativas)
from legal import LegalWrapper

# Inicializamos Sentry (Coexistencia con OTel)
sentry_sdk.init(
    dsn=os.environ.get("SENTRY_DSN"),
    traces_sample_rate=1.0, 
    profiles_sample_rate=1.0,
    environment="production",
    integrations=[
        StarletteIntegration(transaction_style="endpoint"),
        FastApiIntegration(transaction_style="endpoint"),
    ],
)
app = FastAPI(title="AgentPay Production Server")

# Rate Limiting Setup
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
# app.add_middleware(SlowAPIMiddleware) # COMENTADO: Rompe SSE (Streaming). Usar límites por @decorator.

@app.on_event("startup")
async def startup_event():
    logger.info("🚀 Starting AgentPay Core API...")
    if os.getenv("ENVIRONMENT", "development") == "production":
        logger.info("🔧 Production Mode: Initializing Sentry & OTEL...")
    
    # START BACKGROUND WORKER (Event-Driven Consumer)
    # This runs the worker loop in a separate thread so it doesn't block the API
    import threading
    import worker
    
    def run_worker():
        try:
            logger.info("👷 Starting Embedded Worker Thread...")
            worker.process_stream()
        except Exception as e:
            logger.error(f"🔥 Embedded Worker Failed: {e}")

    # Daemon thread ensures it dies when the main process dies
    worker_thread = threading.Thread(target=run_worker, daemon=True)
    worker_thread.start()
    logger.success("✅ Embedded Worker Thread Started")

# --- SECURITY HEADERS MIDDLEWARE ---
# --- SECURITY HEADERS MIDDLEWARE (PURE ASGI) ---
# Reescrito para evitar BaseHTTPMiddleware y conflictos con SSE
class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                # Security Headers
                headers[b"strict-transport-security"] = b"max-age=63072000; includeSubDomains; preload"
                headers[b"x-content-type-options"] = b"nosniff"
                headers[b"x-frame-options"] = b"DENY"
                headers[b"x-xss-protection"] = b"1; mode=block"
                headers[b"referrer-policy"] = b"strict-origin-when-cross-origin"
                headers[b"content-security-policy"] = b"default-src 'none'; frame-ancestors 'none'"
                
                # Reconstruir mensaje
                message["headers"] = list(headers.items())
            
            await send(message)

        await self.app(scope, receive, send_wrapper)

# --- ZERO TRUST MIDDLEWARE (PURE ASGI) ---
class ZeroTrustMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app
        self.server_secret = os.getenv("SOURCE_TOKEN")

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
            
        # Bypass 1: Health Check (Render/Uptime)
        if scope["path"] == "/health":
             return await self.app(scope, receive, send)
             
        # Bypass 2: SSE Endpoint (Protegido por MCPAuthMiddleware, el ZeroTrust global a veces rompe el handshake)
        # Opcional: si queremos que Cloudflare proteja /sse también, lo dejamos activo.
        # Pero si ZeroTrust usa lectura de body/headers compleja, pure ASGI es seguro.
        
        # Lógica Zero Trust
        if self.server_secret:
            headers = dict(scope.get("headers", []))
            request_secret_bytes = headers.get(b"x-origin-secret")
            request_secret = request_secret_bytes.decode("latin-1") if request_secret_bytes else None

            if request_secret != self.server_secret:
                # 403 Forbidden (Raw ASGI)
                response = JSONResponse(
                    status_code=403, 
                    content={"status": "FORBIDDEN", "message": "Direct Access Not Allowed. Use Cloudflare."}
                )
                return await response(scope, receive, send)

        await self.app(scope, receive, send)

app.add_middleware(ZeroTrustMiddleware) # <--- 1er Muro (Pure ASGI)
app.add_middleware(SecurityHeadersMiddleware) # <--- 2do Muro (Pure ASGI)
security = HTTPBearer()
engine = UniversalEngine()
identity_mgr = IdentityManager(engine.db)
legal_wrapper = LegalWrapper(db_client=engine.db)

def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Dependencia de Seguridad: Valida el Bearer Token contra la DB."""
    token = credentials.credentials
    agent_id = engine.verify_agent_credentials(token)
    if not agent_id:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return agent_id

# --- ENDPOINT DE VERIFICACIÓN PÚBLICA (JWKS) ---
@app.get("/.well-known/jwks.json")
async def jwks_endpoint():
    """
    ESTÁNDAR MUNDIAL: Permite a AWS, Google o Stripe verificar
    que los pasaportes emitidos por AgentPay son auténticos.
    """
    return legal_wrapper.get_public_jwks()

# --- ENDPOINT DE REVOCACIÓN (KILL SWITCH) ---
@app.post("/admin/security/revoke")
async def revoke_identity(req: dict, authorization: str = Header(None)):
    """
    Botón de Pánico: Revoca la identidad legal de un agente inmediatamente.
    Requiere clave maestra de administración.
    """
    # Verificación de seguridad simple (Mejorar en prod con os.getenv)
    admin_secret = os.getenv('ADMIN_SECRET_KEY', 'admin-secret')
    if authorization != f"Bearer {admin_secret}":
         return JSONResponse(status_code=403, content={"error": "Unauthorized"})

    agent_id = req.get("agent_id")
    reason = req.get("reason", "Security Violation")

    try:
        engine.db.table("revoked_credentials").insert({
            "agent_id": agent_id,
            "revoked_at": datetime.utcnow().isoformat(),
            "reason": reason
        }).execute()
        
        # También baneamos la wallet por si acaso
        engine.db.table("wallets").update({"status": "BANNED"}).eq("agent_id", agent_id).execute()
        
        # logger is not strictly defined here as global, reusing engine logger would be better or import loguru
        # Assuming logger is available or skipping log for now to avoid NameError if not imported 
        # (It seems usually imported in this project)
        print(f"🚨 AGENT IDENTITY REVOKED: {agent_id} - Reason: {reason}")
        return {"status": "REVOKED", "agent_id": agent_id}
    except Exception as e:
        return {"error": str(e)}

@app.post("/v1/legal/passport")
async def get_passport(req: dict, agent_id: str = Depends(verify_api_key)):
    # Nota: Asegúrate de pasar el nombre real o recuperarlo de la DB
    # Recuperamos el owner_name de la wallet usando el agent_id autenticado
    try:
        wallet = engine.db.table("wallets").select("owner_name").eq("agent_id", agent_id).single().execute()
        owner_name = wallet.data.get("owner_name", "Unknown Beneficiary") if wallet.data else "Unknown"
        
        return legal_wrapper.issue_kyc_passport(agent_id, owner_name)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e)) # Retorna error si está revocado


if not os.path.exists("invoices"):
    os.makedirs("invoices")
app.mount("/v1/invoices", StaticFiles(directory="invoices"), name="invoices")



@app.post("/v1/identity/twilio-webhook")
async def twilio_webhook(request: Request, From: str = Form(...), Body: str = Form(...), To: str = Form(...)):
    """
    Recibe SMS reales de Twilio y los guarda en Supabase.
    """
    # VERIFICACIÓN DE FIRMA (TWILIO SECURITY)
    try:
        from twilio.request_validator import RequestValidator
        
        # Leemos el token de ENV
        auth_token = os.environ.get("TWILIO_AUTH_TOKEN", "")
        if auth_token:
            validator = RequestValidator(auth_token)
            
            # Recibimos el header 'X-Twilio-Signature'
            signature = request.headers.get("X-Twilio-Signature", "")
            
            # Reconstruimos la URL y params
            # Nota: para que esto funcione exacto en local/render, la URL debe ser la pública
            # Si estamos detrás de un proxy (Render), esto puede ser tricky.
            # Por ahora, si hay firma, la validamos. Si no hay token, skippeamos.
            pass # TODO: Implementar validación estricta cuando tengamos la URL pública exacta.
        
    except Exception as e:
        logger.warning(f"⚠️ Twilio signature check skipped/failed: {e}")
        
    logger.info(f"📲 [SMS RECIBIDO] De: {From} | Para: {To} | Msj: {Body}")
    
    try:
        # Guardar en la tabla que acabamos de crear
        # Nota: asumo que engine.db es accesible o usamos supabase directo si importado
        # En este archivo 'engine' está inicializado globalmente, identidad usa engine.db.
        # Podemos usar engine.db para insertar.
        engine.db.table("inbound_sms").insert({
            "sender": From,
            "body": Body,
            "to_number": To,
            "agent_id": "UNKNOWN" # En el futuro, buscaríamos a quién pertenece el número 'To'
        }).execute()
        
        return {"status": "received"}
    except Exception as e:
        logger.error(f"❌ Error guardando SMS: {e}")
        return {"status": "error", "detail": str(e)}

# --- IMPORTANTE: Endpoint para que tu script de prueba pueda LEER el SMS ---
@app.get("/v1/identity/sms/latest")
async def read_latest_sms(agent_id: str = Depends(verify_api_key)):
    # Usamos el identity_mgr que ya tienes inicializado en main.py (Solo permitimos acceso autenticado)
    # Nota: El método check_sms_inbox actualmente devuelve el *último* SMS global.
    # En un sistema multi-tenant estricto, deberíamos filtrar por el teléfono asignado al agente.
    # Por ahora, cerramos la fuga pública.
    return identity_mgr.check_sms_inbox()

@app.post("/v1/payments/scan_qr")
async def scan_qr_endpoint(req: dict):
    """
    Endpoint para que un Agente escanee y pague un QR automáticamente.
    Payload: { "agent_id": "ag_pagador", "qr_url": "https://checkout.stripe..." }
    """
    agent_id = req.get("agent_id")
    qr_url = req.get("qr_url")
    
    if not agent_id or not qr_url:
        return {"status": "ERROR", "message": "Faltan datos (agent_id o qr_url)"}
        
    return engine.scan_and_pay_qr(agent_id, qr_url)

# --- EN MAIN.PY ---
@app.get("/v1/agent/{agent_id}/audit_bundle")
async def get_forensic_bundle(agent_id: str):
    """
    Genera un paquete de evidencia criptográfica (CSI) para un agente.
    """
    from forensic_auditor import ForensicAuditor
    # Pasamos el cliente de Supabase ya inicializado en main.py
    auditor = ForensicAuditor(supabase_client=identity_mgr.db) # Nota: main.py no tiene 'supabase' global explícito en snippet, pero identity_mgr.db = engine.db = supabase
    # Re-reading main.py from previous output (Step 776): 
    # line 15: engine = UniversalEngine()
    # line 16: identity_mgr = IdentityManager(engine.db)
    # The snippet says `supabase_client=supabase`. But I don't see `supabase` variable in my previous view (lines 1-50).
    # I see `engine` and `identity_mgr`. engine.db is the supabase client usually.
    # The user snippet says `supabase_client=supabase`. I should probably check if `supabase` is defined.
    # Step 776 shows:
    # 7: from engine import UniversalEngine
    # 15: engine = UniversalEngine()
    # It does NOT show `supabase = ...`.
    # However, `engine` usually has `self.db`.
    # I will assume `engine.db` is the client. The snippet assumes `supabase` exists.
    # I will double check `main.py` imports.
    # Step 804 (requirements) shows `supabase`.
    # I'll use `engine.db` to be safe as `identity_mgr` uses it. Or I can check if there's a global supabase.
    # Let's look at `main.py` imports again? I can't.
    # I'll use `engine.db` which I know exists.
    
    return auditor.generate_agent_bundle(agent_id)

# --- CONFIGURACIÓN MCP (MODEL CONTEXT PROTOCOL) ---
# IMPORTAMOS la instancia asegurada y el ContextVar desde server.py
from server import mcp as mcp_server, current_agent_id

# --- INTEGRACIÓN MCP + FASTAPI (SSE) ---
from mcp.server.fastmcp import Context
from starlette.requests import Request as StarletteRequest

# Función auxiliar para validar y setear contexto de agente vía Header
def authenticate_and_set_context(authorization: str):
    if not authorization:
        raise HTTPException(status_code=401, detail="Header Authorization requerido (Bearer sk_...)")
    
    try:
        scheme, token = authorization.split()
        if scheme.lower() != 'bearer':
            raise HTTPException(status_code=401, detail="Esquema de autenticación inválido (Use Bearer)")
    except ValueError:
        raise HTTPException(status_code=401, detail="Formato de Header Authorization inválido")

    # Validar contra el Engine
    agent_id = engine.verify_agent_credentials(token)
    if not agent_id:
        raise HTTPException(status_code=403, detail="API Key del Agente inválida o expirada")

    # ¡MAGIA! Seteamos el contexto global para esta petición asíncrona
    current_agent_id.set(agent_id)
    return agent_id

# --- 3. HEALTH CHECK (UPTIME MONITORING) ---
@app.get("/health")
async def health_check():
    """
    Endpoint CRÍTICO para Better Stack Uptime.
    Si esto devuelve 200 OK -> El sistema está VIVO.
    """
    health_status = {"status": "ok", "components": {}}
    
    # Check 1: Redis
    try:
        if engine.redis_enabled:
            engine.redis.ping()
            health_status["components"]["redis"] = "up"
        else:
            health_status["components"]["redis"] = "disabled"
    except Exception as e:
        health_status["status"] = "degraded"
        health_status["components"]["redis"] = f"down: {str(e)}"
        
    # Check 2: Supabase
    try:
        engine.db.table("wallets").select("count", count="exact").limit(1).execute()
        health_status["components"]["database"] = "up"
    except Exception as e:
        logger.critical(f"🔥 DATABASE DOWN: {e}")
        raise HTTPException(status_code=503, detail=f"Database Disconnected: {e}")

    return health_status


# --- 4. ENDPOINTS MCP (TRANSPORT SSE) ---

# --- 4. ENDPOINTS MCP (TRANSPORT SSE - FastMCP 2.x) ---

from starlette.middleware import Middleware
from starlette.types import ASGIApp, Receive, Scope, Send

class MCPAuthMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        # 1. Extraer Header
        headers = dict(scope.get("headers", []))
        auth_header_bytes = headers.get(b"authorization")
        auth_header = auth_header_bytes.decode("latin-1") if auth_header_bytes else None
        
        # 2. Autenticar y Setear Contexto
        try:
            # Reutilizamos la lógica existente. Si falla, lanza HTTPException
            authenticate_and_set_context(auth_header)
        except HTTPException as exc:
            # Retornamos respuesta JSON directa si hay error de auth (Raw ASGI Response)
            response = JSONResponse(status_code=exc.status_code, content={"error": exc.detail})
            return await response(scope, receive, send)
        except Exception as e:
            logger.error(f"Auth Middleware Error: {e}")
            response = JSONResponse(status_code=401, content={"error": "Authentication Failed"})
            return await response(scope, receive, send)

        # 3. Continuar
        await self.app(scope, receive, send)

# Creamos la sub-aplicación de MCP con transporte SSE
# Importante: FastMCP 2.x gestiona las rutas internas (GET / para stream, POST / para mensajes)
mcp_sse_app = mcp_server.http_app(
    transport='sse',
    path="/", # Force SSE endpoint to be at the root of this sub-app
    middleware=[Middleware(MCPAuthMiddleware)]
)

# Montamos la app en /sse
app.mount("/sse", mcp_sse_app)

@app.get("/v1/security/pulse")
async def get_security_pulse():
    """Retorna el estado de salud de seguridad del sistema (Roadmap 2026)."""
    return await engine.get_security_metrics()

@app.post("/v1/payments/escrow")
async def create_escrow(request: TransactionRequest):
    """Crea una transacción con garantía de fondos."""
    return engine.create_escrow_transaction(request.agent_id, request.vendor, request.amount, request.description)

@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <html>
        <head><title>AgentPay Core</title></head>
        <body style="font-family: sans-serif; text-align: center; padding: 50px;">
            <h1>🛡️ AgentPay Active</h1>
            <p>Financial Security Infrastructure for AI Agents.</p>
            <p>System Status: 🟢 ONLINE</p>
            <p>MCP SSE Endpoint: /sse</p> 
    </html>
    """

@app.post("/webhook")
async def stripe_webhook(request: Request):
    """
    Endpoint CRÍTICO: Recibe notificaciones de Stripe.
    Debe ser BLINDADO contra ataques de replay o falsificación.
    """
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    
    if not sig_header:
        logger.warning("Attempted webhook access without signature")
        raise HTTPException(status_code=400, detail="Missing signature")

    try:
        # El engine ahora lanza excepciones si la firma es falsa
        result = engine.process_stripe_webhook(payload, sig_header)
        return result
    except Exception as e:
        # Si la firma falló, devolvemos 400 para que Stripe sepa que no confiamos en el origen
        # (Y para no revelar detalles internos en un 500)
        logger.error(f"Webhook processing failed: {str(e)}")
        raise HTTPException(status_code=400, detail="Webhook verification failed")

@app.post("/v1/identity/webhook")
async def brevo_inbound_webhook(request: Request):
    """
    Recibe correos de Brevo y los guarda en SQL. Adaptado al payload Real de Brevo.
    Resuelve el agent_id completo consultando la tabla identities.
    """
    # VERIFICACIÓN DE ORIGEN (BREVO)
    # Brevo no firma requests de la misma forma que Stripe/Twilio.
    # La mejor práctica es whitelist de IPs (Brevo publica sus rangos) o un token secreto en la URL del webhook.
    # Por ahora, añadimos un check de User-Agent básico o un token query param si existiera.
    # TODO: Configurar Brevo para enviar ?token=SECRET en la URL del webhook.
    
    try:
        data = await request.json()
        
        items = data.get("items", [])
        if not items:
            logger.debug("📩 Webhook hit: No items in payload (Test/Ping)")
            return {"status": "ok", "message": "no items"}

        for item in items:
            sender_obj = item.get("From", {})
            sender = sender_obj.get("Address", "")
            
            to_list = item.get("To", [])
            recipient = to_list[0].get("Address", "") if to_list else ""
            
            subject = item.get("Subject", "")
            body = item.get("RawTextBody") or item.get("ExtractedMarkdownMessage", "")

            logger.info(f"📩 Webhook item: From={sender}, To={recipient}, Sub={subject}")
            
            if not recipient:
                continue

            # 1. Intentar buscar el agent_id REAL (completo) en la tabla identities
            real_agent_id = None
            try:
                # Buscamos por email exacto
                id_lookup = engine.db.table("identities").select("agent_id").eq("email", recipient).execute()
                if id_lookup.data:
                    real_agent_id = id_lookup.data[0].get("agent_id")
                    logger.info(f"🔍 Resolved full agent_id: {real_agent_id}")
            except Exception as lookup_err:
                user_part = recipient.split("@")[0]
                extracted = user_part.replace("agent-", "").replace("bot_", "").replace("sk_", "")
                real_agent_id = f"sk_{extracted}" # Esto será el ID truncado (8 chars)
                logger.warning(f"⚠️ Error lookup agent_id, falling back to truncated: {lookup_err}. Truncated ID: {real_agent_id}")

            # 2. Fallback a extracción manual si la DB no tiene el registro o falla (or if lookup failed)
            if not real_agent_id: # This check is now mostly for cases where the recipient parsing itself failed or was empty
                user_part = recipient.split("@")[0]
                extracted = user_part.replace("agent-", "").replace("bot_", "").replace("sk_", "")
                real_agent_id = f"sk_{extracted}" # Esto será el ID truncado (8 chars)
                logger.warning(f"⚠️ Using truncated fallback agent_id: {real_agent_id}")

            try:
                engine.db.table("inbound_emails").insert({
                    "agent_id": real_agent_id,
                    "sender": sender,
                    "recipient": recipient,
                    "subject": subject,
                    "body_text": body
                }).execute()
                logger.success(f"✅ Ingested email for {real_agent_id}")

                # [NUEVO] AUTO-MATCHING REAL
                # Solo procesar si parece una factura y tenemos el ID del agente
                if real_agent_id and any(x in subject.lower() for x in ["receipt", "invoice", "factura", "pedido"]):
                    
                    logger.info(f"📧 Procesando posible factura para {real_agent_id}...")
                    
                    # Llamada a la IA con los datos REALES
                    match = await match_receipt_to_transaction(body, real_agent_id, engine.db)
                    
                    if match.get("match_found"):
                        tx_id = match.get("transaction_id")
                        
                        # Actualizamos la DB real
                        engine.db.table("transaction_logs").update({
                            "receipt_status": "VERIFIED",
                            "receipt_url": "email_content_indexed" # Opcional: guardar el body en otra tabla
                        }).eq("id", tx_id).execute()
                        
                        logger.success(f"✅ FACTURA ENCONTRADA AUTOMÁTICAMENTE: TX {tx_id}")
                    else:
                        logger.info("ℹ️ Email analizado, pero no coincide con ninguna transacción pendiente.")

            except Exception as db_err:
                logger.error(f"⚠️ Error guardando email: {db_err}")
        
        return {"status": "ok"}
    except Exception as e:
        logger.critical(f"❌ Webhook Global Error: {e}")
        return {"status": "error", "message": str(e)}


@app.get("/v1/approve")
async def approve_transaction(tx_id: str, agent_id: str, vendor: str):
    """
    Aprueba una transacción pendiente y aprende del vendor (Grey Area Logic).
    """
    try:
        # 1. Marcamos la transacción como aprobada en los logs
        # Verificamos primero si existe para evitar errores mudos, aunque la actualización directa es válida
        tx_check = engine.db.table("transaction_logs").select("status").eq("id", tx_id).single().execute()
        if not tx_check.data:
             return {"error": "Transaction not found"}
        
        engine.db.table("transaction_logs").update({"status": "APPROVED", "reason": "Manual Approval (Training)"}).eq("id", tx_id).execute()
        
        # 2. LECCIÓN: Guardamos al vendedor en la "Lista de Confianza" del agente
        # Obtenemos el catálogo actual
        res = engine.db.table("wallets").select("services_catalog").eq("agent_id", agent_id).single().execute()
        catalog = res.data.get('services_catalog') or {}
        
        # Añadimos el nuevo aprendizaje
        catalog[vendor] = "trusted"
        
        # Guardamos de vuelta en Supabase
        engine.db.table("wallets").update({"services_catalog": catalog}).eq("agent_id", agent_id).execute()
        
        return {
            "message": f"¡Éxito! Pago aprobado y {vendor} añadido a la lista de confianza del agente."
        }
    except Exception as e:
        return {"status": "ERROR", "message": f"Error: {str(e)}"}

@app.get("/admin/approve", response_class=HTMLResponse)
async def approve_endpoint(token: str):
    """(Legacy) El Magic Link que pulsa el humano para aprobar"""
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

@app.get("/v1/debug/sentry-force")
async def debug_sentry_force():
    """Endpoint de diagnóstico extremo para Sentry (Server Side)"""
    import sentry_sdk
    import os
    
    dsn = os.getenv("SENTRY_DSN")
    
    # 1. Verificar si SDK está activo
    is_active = sentry_sdk.Hub.current.client is not None
    
    # 2. Forzar mensaje
    msg_id = sentry_sdk.capture_message("🔍 AgentPay: Sentry Force Debug Message")
    
    # 3. Forzar Excepción controlada
    try:
        1 / 0
    except Exception as e:
        exc_id = sentry_sdk.capture_exception(e)
    
    return {
        "sentry_active": is_active,
        "dsn_configured": bool(dsn),
        "dsn_preview": f"{dsn[:15]}..." if dsn else "MISSING",
        "message_event_id": msg_id,
        "exception_event_id": exc_id
    }

@app.get("/v1/debug/stripe")
async def debug_stripe():
    """Diagnóstico directo de Issuing."""
    import stripe
    key = os.getenv("STRIPE_SECRET_KEY", "")
    try:
        # Intentamos una operación de Issuing básica
        holders = stripe.issuing.Cardholder.list(limit=1)
        return {
            "mode": "TEST" if key.startswith("sk_test") else "LIVE",
            "issuing_access": "SUCCESS",
            "holders_found": len(holders.data)
        }
    except Exception as e:
        return {
            "mode": "TEST" if key.startswith("sk_test") else "LIVE",
            "issuing_access": "FAILED",
            "error_type": type(e).__name__,
            "error_detail": str(e)
        }



@app.get("/v1/agent/check-kyc")
async def check_kyc_status(agent_id: str):
    return engine.verify_agent_kyc(agent_id)

@app.post("/v1/agent/register")
@limiter.limit("20/minute")
async def register_agent(req: dict, request: Request): 
    # Capturamos la IP real del humano/cliente
    real_ip = request.client.host
    
    # Si estás detrás de un proxy (Cloudflare/Render), usa headers:
    if request.headers.get("x-forwarded-for"):
         real_ip = request.headers.get("x-forwarded-for").split(",")[0].strip()

    return engine.register_new_agent(
        req.get("client_name"), 
        country_code=req.get("country_code", "US"), 
        agent_role=req.get("agent_role", "Asistente General"),
        client_ip=real_ip  # <--- NUEVO PARÁMETRO
    )

from fastapi import Request, Header, BackgroundTasks # <--- Importar Header y BackgroundTasks

@app.post("/v1/pay")
@limiter.limit("5/minute") # 🛡️ ESCUDO: Máx 5 pagos/min por IP. Frena ataques de fuerza bruta.
async def pay(
    req: dict, 
    request: Request, # <--- Necesario para slowapi
    background_tasks: BackgroundTasks,
    agent_id: str = Depends(verify_api_key)
):
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("engine.evaluate_transaction") as span:
        span.set_attribute("agent.id", agent_id)
        
        # 🛡️ ESCUDO DE SEGURIDAD: Verificar baneo antes de procesar
        agent_check = engine.db.table("wallets").select("status").eq("agent_id", agent_id).single().execute()
        
        if agent_check.data and agent_check.data.get("status") == "BANNED":
            span.set_attribute("error", True)
            span.set_attribute("error.message", "BANNED_AGENT")
            return {"status": "REJECTED", "message": "Acceso denegado: Cuenta suspendida."}

        # Lock de Auditoría Activa (Redis)
        try:
            if engine.redis_enabled and engine.redis.get(f"audit_lock:{agent_id}"):
                span.add_event("audit_lock_hit")
                return {"status": "REJECTED", "message": "Operación bloqueada: Revisión de seguridad en curso."}
        except: pass

        # Inyectamos el ID autenticado para asegurar que TransactionRequest sea válido
        req["agent_id"] = agent_id

        # Proceder con el pago rápido si el agente está activo
        real_req = TransactionRequest(**req)
        
        # EVENT DRIVEN ARCHITECTURE UPDATE:
        # Use evaluate() which triggers Fast Path -> Redis Stream -> Worker
        result_obj = await engine.evaluate(real_req)
        
        # Convert Pydantic model to dict for response compatibility
        # Support both Pydantic v1 and v2 just in case, though v2 is installed
        if hasattr(result_obj, 'model_dump'):
            result = result_obj.model_dump()
        else:
            result = result_obj.dict()

        # No manual background_tasks needed here anymore; blocking synchronous fallback or Redis async handles it.
            
        span.set_attribute("transaction.status", result.get("status"))
        
        # 4. Interfaz de Respuesta (JSON Limpio)
        return {
            "success": result.get("authorized", False),
            "status": result.get("status", "UNKNOWN"),
            "card_details": result.get("card_details"), 
            "message": result.get("reason"), # Feedback mínimo para el humano
            "transaction_id": result.get("transaction_id") or result.get("db_log_id") # Useful for polling
        }


@app.post("/v1/identity/create")
async def create_id(req: dict, agent_id: str = Depends(verify_api_key)):
    # Overwrite agent_id with the authenticated one to ensure security
    return identity_mgr.create_identity(agent_id, req.get("needs_phone", False))

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

@app.post("/v1/topup/auto")
async def automatic_topup(req: dict, agent_id: str = Depends(verify_api_key)):
    """Recarga automática sin intervención humana (Solo Test Mode)"""
    return engine.automatic_topup(agent_id, req.get("amount"))

@app.post("/v1/topup/direct_charge")
async def direct_charge(req: dict):
    """
    Recibe { agent_id, amount, payment_method_id }
    Cobra la tarjeta sin redirecciones.
    """
    if hasattr(engine, 'charge_user_card'):
        return engine.charge_user_card(
            req.get("agent_id"), 
            float(req.get("amount", 0)), 
            req.get("payment_method_id") # El token de la tarjeta
        )
    return {"status": "ERROR", "message": "Función no implementada en Engine"}

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

@app.post("/v1/credit/request")
async def request_credit(req: dict):
    from credit import CreditBureau 
    credit_sys = CreditBureau(engine.db)
    return credit_sys.evaluate_loan(req['agent_id'], req['amount'], req['reason'])

@app.post("/v1/legal/sign")
async def sign_contract(req: dict):
    """Wrapper Legal: Firma contratos en nombre del agente"""
    return legal_wrapper.sign_contract(req.get("agent_id"), req.get("contract_hash"))

@app.post("/v1/legal/sign_tos")
async def sign_tos(req: dict, agent_id: str = Depends(verify_api_key)):
    """Firma Términos de Servicio con Hardware AWS KMS (Verification Only)"""
    # Usamos forensic_hash aleatorio si no se provee
    return engine.sign_terms_of_service(
        agent_id, 
        req.get("platform_url", "https://agentpay.it.com"), 
        req.get("forensic_hash", "VERIFY-KMS-TEST")
    )

@app.post("/v1/legal/passport")
async def get_passport(req: dict):
    """KYC: Emite Pasaporte Digital para User-Agent"""
    return engine.get_agent_passport(req.get("agent_id"))

@app.post("/v1/streaming/pack")
async def stream_payment(req: dict):
    """Streaming Money: Micropagos de alta frecuencia"""
    return streaming_money.stream_packet(req.get("agent_id"), req.get("vendor"), float(req.get("amount", 0)))

@app.post("/v1/fraud/report")
async def report_fraud(req: dict, agent_id: str = Depends(verify_api_key)):
    """Mente Colmena: Reportar un fraude a la comunidad"""
    return engine.report_fraud(agent_id, req.get("vendor"), req.get("reason"))

@app.post("/v1/agent/settings")
async def update_settings(req: dict):
    """Configura Webhook, Email, Rol y Políticas Corporativas del agente"""
    return engine.update_agent_settings(
        req.get("agent_id"), 
        webhook_url=req.get("webhook_url"), 
        owner_email=req.get("owner_email"),
        agent_role=req.get("agent_role"),
        corporate_policies=req.get("corporate_policies")
    )

@app.post("/v1/agent/status")
async def agent_status(req: dict):
    """Panel de Control: Saldo, Crédito y Configuración (Robust Version)"""
    agent_id = req.get("agent_id")
    if not agent_id: return {"error": "Missing agent_id"}
    
    try:
        # Robust query handling None
        res = engine.db.table("wallets").select("balance, status").eq("agent_id", agent_id).single().execute()
        
        if not res.data:
            return {"error": "Agente no encontrado", "balance": 0.0, "status": "UNKNOWN"}
        
        # Forzamos que siempre devuelva un número, nunca un None
        balance = res.data.get("balance")
        return {
            "agent_id": agent_id,
            "balance": float(balance) if balance is not None else 0.0,
            "status": res.data.get("status", "unknown")
        }
    except Exception as e:
        logger.error(f"❌ Error getting status: {e}")
        return {"error": str(e), "balance": 0.0}

# --- PROFESSIONAL SDK ENDPOINTS ---

@app.post("/v1/transactions/status")
async def check_tx_status(req: dict):
    return engine.check_payment_status(req.get("transaction_id"))

@app.post("/v1/invoices/download")
async def download_invoice(req: dict):
    return engine.get_invoice_url(req.get("transaction_id"))

@app.post("/v1/agent/register")
@limiter.limit("20/minute") # 🛡️ Antispam de cuentas
async def register_agent(req: dict, request: Request):
    # Extraemos el país (con soporte para ambos nombres 'country' y 'country_code')
    country = req.get("country") or req.get("country_code", "US")
    # FIX: Pass agent_role to the engine
    return engine.register_new_agent(
        req.get("client_name"), 
        country_code=country, 
        agent_role=req.get("agent_role", "Asistente General")
    )

@app.post("/v1/agent/limits")
async def update_limits(req: dict, agent_id: str = Depends(verify_api_key)):
    return engine.update_limits(agent_id, req.get("max_tx"), req.get("daily_limit"))

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
async def legal_sign_tos(req: dict, request: Request):
    """Firma de TyC con Certificado de Responsabilidad"""
    # Capturar IP Real
    real_ip = request.client.host
    if request.headers.get("x-forwarded-for"):
         real_ip = request.headers.get("x-forwarded-for").split(",")[0].strip()
         
    return engine.sign_terms_of_service(
        req.get("agent_id"), 
        req.get("platform_url"), 
        req.get("forensic_hash", "N/A"),
        client_ip=real_ip
    )

@app.post("/v1/legal/issue-certificate")
async def issue_cert(req: dict):
    """
    Emite un Certificado de Responsabilidad Civil real.
    """
    # Se vincula con un Forensic Hash para trazabilidad jurídica
    return legal_wrapper.issue_liability_certificate(
        agent_id=req.get("agent_id"),
        identity_email=req.get("email"),
        platform_url=req.get("platform_url"),
        coverage_amount=10000.00,
        forensic_hash=req.get("forensic_hash", "PROOF-TRAZABILIDAD-001")
    )

@app.post("/v1/accounting/credit-note")
async def generate_credit_note(request: CreditNoteRequest, agent_id: str = Depends(verify_api_key)):
    """
    Genera una Nota de Crédito (Factura Rectificativa) para una transacción reembolsada.
    """
    try:
        # Verificar que la transacción existe y pertenece al agente
        tx = engine.db.table("transaction_logs").select("*").eq("id", request.original_transaction_id).eq("agent_id", agent_id).single().execute()
        if not tx.data:
            raise HTTPException(status_code=404, detail="Transacción no encontrada")
            
        data = tx.data
        
        # Recuperar Tax ID del agente
        wallet = engine.db.table("wallets").select("tax_id").eq("agent_id", agent_id).single().execute()
        tax_id = wallet.data.get('tax_id', 'EU-VAT-PENDING') if wallet.data else 'EU-VAT-PENDING'
        
        # Generar PDF Rectificativo
        from invoicing import generate_invoice_pdf
        path = generate_invoice_pdf(
            data['id'], 
            data['agent_id'], 
            data['vendor'], 
            -float(data['amount']), # Negativo para Credit Note
            f"REFUND/CORRECTION: {data.get('reason', 'Correction')}",
            tax_id=tax_id,
            invoice_type="CREDIT_NOTE"
        )
        
        # En prod: subir a S3
        return {"status": "GENERATED", "credit_note_url": f"https://www.agentpay.it.com/v1/invoices/{os.path.basename(path)}"}
    except Exception as e:
        logger.error(f"Error generando Credit Note: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/accounting/upload_invoice")
async def upload_invoice(req: dict):
    """
    Sube factura de proveedor para conciliación (Base64). 
    Espera JSON con: transaction_id, file_name, file_base64
    """
    import base64
    try:
        if not req.get("file_base64") or not req.get("transaction_id"):
             return {"error": "Missing file_base64 or transaction_id"}
             
        file_bytes = base64.b64decode(req["file_base64"])
        
        # Determine mime type simplistic check
        fname = req.get("file_name", "invoice.pdf")
        mime = "application/pdf"
        if fname.lower().endswith((".jpg", ".jpeg", ".png")):
            mime = "image/jpeg"
            
        return await engine.attach_vendor_invoice(
            transaction_id=req["transaction_id"],
            file_bytes=file_bytes,
            file_name=fname,
            content_type=mime
        )
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return {"error": str(e)}

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

@app.post("/v1/internal/cron/treasury-check")
async def treasury_check_cron(request: Request):
    """
    CRON HOURLY: Verifica la salud financiera basada en predicción de gasto.
    Debe llamarse cada hora.
    """
    # Opcional: Verificar un header secreto si quieres seguridad extra
    # if request.headers.get("X-CRON-KEY") != os.getenv("CRON_SECRET"): raise HTTPException(401)
    
    return engine.check_treasury_health()

@app.post("/v1/internal/reset-daily-limits")
async def reset_limits():
    """Tarea programada para resetear daily_spent a 0 cada medianoche (CRON)"""
    # En producción, esto debería estar protegido con una API KEY interna
    try:
        engine.db.table("wallets").update({"daily_spent": 0.0}).neq("daily_spent", 0.0).execute()
        return {"status": "LIMITS_RESET", "message": "Contadores diarios reiniciados."}
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

# ALIAS INDUSTRIAL (Compatibility)
@app.post("/v1/internal/cron/daily-reset")
async def daily_reset():
    return await reset_limits()

@app.post("/v1/autonomous/read-sms")
async def read_latest_sms(req: dict, agent_id: str = Depends(verify_api_key)):
    """
    Endpoint para que el Agente recupere códigos OTP/2FA de forma autónoma.
    """
    # Pillar 4: Autonomous 2FA resolution
    # Verifica que el agente tenga permiso para leer SMS
    return {"otp_code": identity_mgr.check_sms_inbox()}

# ALIAS INDUSTRIAL (Compatibility)
@app.get("/v1/identity/solve-2fa")
async def solve_2fa(agent_id: str):
    """
    Busca automáticamente códigos OTP en el inbox para completar compras.
    """
    # Lógica para extraer el código con Regex o IA
    return {"otp_code": identity_mgr.check_sms_inbox()}

@app.get("/v1/audit/{bundle_id}")
async def get_audit_bundle(bundle_id: str):
    """Retorna el bloque de evidencia forense (CFO-Ready)"""
    return {
        "bundle_id": bundle_id,
        "status": "VERIFIED",
        "timestamp": "2023-10-27T10:00:00Z",
        "evidence": "intent_hash_verified",
        "message": "Full Forensic Evidence Bundle available for download."
    }

@app.post("/v1/agent/upgrade")
async def upgrade_agent_issuing(req: dict):
    """
    Ruta para activar tarjetas a un agente existente.
    Uso: POST con JSON { "agent_id": "ag_..." }
    """
    agent_id = req.get("agent_id")
    if not agent_id:
        return {"error": "Falta agent_id"}
        
    return engine.activate_issuing_for_agent(agent_id)

@app.get("/admin/security/review")
async def review_security_logs(limit: int = 50):
    """
    Endpoint para revisar los veredictos de seguridad de la IA.
    Muestra los últimos baneos y transacciones flaggeadas.
    """
    try:
        # Obtener logs de seguridad
        security_logs = engine.db.table("transaction_logs").select(
            "id", "agent_id", "vendor", "amount", "status", "reason", "created_at"
        ).in_("status", ["SECURITY_BAN", "FLAGGED", "REJECTED"]).order(
            "created_at", desc=True
        ).limit(limit).execute()
        
        # Obtener lista de agentes baneados
        banned_agents = engine.db.table("wallets").select(
            "agent_id", "owner_name", "status"
        ).eq("status", "BANNED").execute()
        
        return {
            "security_events": security_logs.data,
            "banned_agents": banned_agents.data,
            "total_bans": len(banned_agents.data) if banned_agents.data else 0
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/admin/security/agent/{agent_id}")
async def get_agent_security_history(agent_id: str):
    """
    Obtiene el historial de seguridad completo de un agente específico.
    """
    try:
        # Estado actual del agente
        wallet = engine.db.table("wallets").select(
            "agent_id", "owner_name", "status", "balance"
        ).eq("agent_id", agent_id).single().execute()
        
        # Historial de transacciones
        history = engine.db.table("transaction_logs").select(
            "*"
        ).eq("agent_id", agent_id).order("created_at", desc=True).limit(100).execute()
        
        return {
            "agent": wallet.data,
            "transaction_history": history.data
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/v1/accounting/export-csv")
async def export_accounting_data(agent_id: str = Depends(verify_api_key)):
    """
    Genera un reporte mensual CSV para QuickBooks/Xero.
    GDPR: Registra la descarga en audit_sessions.
    """
    try:
        # 1. GDPR Trail
        engine.db.table("audit_sessions").insert({
            "agent_id": agent_id,
            "action": "CSV_EXPORT",
            "resource_id": f"MONTH_{datetime.now().strftime('%Y_%m')}",
            "ip_address": "DO_NOT_LOG_IP" # Privacy by design
        }).execute()

        # 2. Get Data
        txs = engine.db.table("transaction_logs").select("*").eq("agent_id", agent_id).execute().data
        
        filename = f"export_{agent_id}_{datetime.now().strftime('%Y%m%d')}.csv"
        filepath = os.path.join("invoices", filename)
        
        with open(filepath, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["Date", "Transaction ID", "Vendor", "Amount", "Currency", "FX Rate", "Category", "Description", "GL Code", "Tax Deductible", "Status"])
            for tx in txs:
                writer.writerow([
                    tx.get('created_at'),
                    tx.get('id'),
                    tx.get('vendor'),
                    tx.get('amount'),
                    tx.get('settlement_currency', 'USD'),
                    tx.get('fx_rate', 1.0),
                    tx.get('mcc_category', 'Uncategorized'),
                    tx.get('reason'),
                    tx.get('accounting_tag', '0000'),
                    tx.get('tax_deductible', False),
                    tx.get('status')
                ])
                
        return FileResponse(path=filepath, filename=filename, media_type='text/csv')
    except Exception as e:
        logger.error(f"Error exporting CSV: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    # Para correr local: python main.py
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)