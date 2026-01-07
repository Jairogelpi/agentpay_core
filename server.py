"""
AgentPay MCP Server - God Mode (Header Secured)
Enterprise-grade security: HTTP Header Auth + ContextVars + Native Middleware
"""
from fastmcp import FastMCP
import sentry_sdk
import json
import os
import stripe
import time
from datetime import datetime
from typing import Optional
from loguru import logger
from contextvars import ContextVar

# Core imports
from models import TransactionRequest, CreditNoteRequest
from engine import UniversalEngine
from identity import IdentityManager
from credit import CreditBureau
from streaming import StreamingMoney
from legal import LegalWrapper
from invoicing import generate_invoice_pdf
from lawyer import AutoLawyer
from arbitration import AIArbiter
from notifications import send_approval_email, send_security_ban_alert, send_treasury_alert_email
from ai_guard import audit_transaction
from integrations import send_slack_approval
from security_utils import check_domain_age
from webhooks import send_webhook
from forensic_auditor import ForensicAuditor
from legal_resources import get_legal_packet

# Initialize Subsystems
engine = UniversalEngine()
identity_mgr = IdentityManager(engine.db)
credit_sys = CreditBureau(engine.db)
streaming_money = StreamingMoney(engine.db)
legal_wrapper = LegalWrapper()
auto_lawyer = AutoLawyer()
ai_arbiter = AIArbiter()
forensic_auditor = ForensicAuditor(engine.db)

# ==========================================
# SECURITY LAYER (ContextVars & Middleware)
# ==========================================

# Variable global que guardará el ID del agente durante la petición (transferred from FastAPI via Header)
current_agent_id: ContextVar[str] = ContextVar("current_agent_id", default=None)

# Rate limiting config
RATE_LIMIT_RPM = int(os.getenv("MCP_RATE_LIMIT_RPM", "60"))

def _check_rate_limit(agent_id: str) -> bool:
    """Redis sliding window rate limiter."""
    if not engine.redis_enabled:
        return True
    key = f"ratelimit:mcp:{agent_id}"
    now = int(time.time())
    try:
        pipe = engine.redis.pipeline()
        pipe.zremrangebyscore(key, 0, now - 60)
        pipe.zadd(key, {str(now): now})
        pipe.zcard(key)
        pipe.expire(key, 60)
        results = pipe.execute()
        return results[2] <= RATE_LIMIT_RPM
    except:
        return True

def _log_mcp_call(agent_id: str, tool_name: str, params: dict, status: str = "OK"):
    """Audit log using UnifiedAuditor (centralized)."""
    try:
        from forensic_auditor import UnifiedAuditor
        auditor = UnifiedAuditor(engine.db)
        auditor.log_mcp_tool(agent_id, tool_name, params, status)
    except Exception as e:
        logger.warning(f"Audit log failed: {e}")

async def auth_middleware(request, call_next):
    """
    FastMCP Native Middleware.
    Reads current_agent_id from ContextVar (set by main.py).
    Applies rate limiting and audit logging.
    """
    agent_id = current_agent_id.get()
    
    # 1. Context Verify
    if not agent_id:
        # If running via STDIO (Direct execution), we might not have the context set via HTTP
        # But for the remote God Mode server, we require it.
        return {"error": "UNAUTHORIZED", "message": "No authenticated context found. Missing Header.", "code": 401}
    
    # 2. Rate Limit
    if not _check_rate_limit(agent_id):
        _log_mcp_call(agent_id, request.name, request.arguments, "RATE_LIMITED")
        return {"error": "RATE_LIMITED", "message": f"Exceeded {RATE_LIMIT_RPM} RPM", "code": 429}
    
    # 3. Execution & Audit
    sentry_sdk.set_user({"id": agent_id})
    try:
        result = await call_next(request)
        _log_mcp_call(agent_id, request.name, request.arguments, "OK")
        return result
    except Exception as e:
        sentry_sdk.capture_exception(e)
        _log_mcp_call(agent_id, request.name, request.arguments, f"ERROR: {type(e).__name__}")
        return {"error": "INTERNAL_ERROR", "message": "An unexpected error occurred.", "code": 500}

# Initialize Server
mcp = FastMCP("AgentPay God Mode")

# Register the middleware for logging & rate limiting
mcp.add_middleware(auth_middleware)

# Helper to get verified agent_id from context
def get_verified_agent_id() -> str:
    """Recupera el ID del agente autenticado vía Header."""
    agent_id = current_agent_id.get()
    if not agent_id:
        raise ValueError("Unauthorized: No Agent ID context found")
    return agent_id

# ==========================================
# 1. CORE FINANCIAL
# ==========================================

@mcp.tool()
def pay_vendor(vendor: str, amount: float, description: str, justification: str = None) -> str:
    """Executes a standard B2B payment. Returns status and receipt."""
    agent_id = get_verified_agent_id()
    req = TransactionRequest(agent_id=agent_id, vendor=vendor, amount=amount, description=description, justification=justification)
    result = engine.evaluate(req)
    return json.dumps({"success": result.authorized, "status": result.status, "tx_id": result.transaction_id, "reason": result.reason, "receipt": result.forensic_bundle_url})

@mcp.tool()
def process_procurement(vendor: str, amount: float, items: list[str], description: str) -> str:
    """[COMPLEX] Executes a procurement order with multiple line items."""
    return json.dumps(engine.process_procurement(get_verified_agent_id(), vendor, amount, items, description))

@mcp.tool()
def issue_virtual_card(amount: float, vendor: str, mcc_category: str = 'services') -> str:
    """[ISSUING] Creates a one-time virtual card for a specific vendor."""
    return json.dumps(engine._issue_virtual_card(get_verified_agent_id(), amount, vendor, mcc_category))

@mcp.tool()
def scan_qr_and_pay(qr_url: str) -> str:
    """[VISION] Reads a Stripe/Payment QR URL and pays it automatically."""
    return json.dumps(engine.scan_and_pay_qr(get_verified_agent_id(), qr_url))

@mcp.tool()
def create_escrow(vendor: str, amount: float, description: str) -> str:
    """[ESCROW] Creates a transaction where funds are held until confirmation."""
    return json.dumps(engine.create_escrow_transaction(get_verified_agent_id(), vendor, amount, description))

@mcp.tool()
def release_escrow(transaction_id: str) -> str:
    """[ESCROW] Confirms delivery and releases funds to vendor."""
    return json.dumps(engine.confirm_delivery(get_verified_agent_id(), transaction_id))

@mcp.tool()
def create_balance_topup(amount: float) -> str:
    """Generates a Stripe Checkout link for a human to add funds to the agent wallet."""
    agent_id = get_verified_agent_id()
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{'price_data': {'currency': 'usd', 'product_data': {'name': f'Agent Topup ({agent_id})'}, 'unit_amount': int(amount * 100)}, 'quantity': 1}],
        mode='payment', metadata={'agent_id': agent_id, 'type': 'TOPUP'},
        success_url="https://agentpay.ai/success?session_id={CHECKOUT_SESSION_ID}", cancel_url="https://agentpay.ai/cancel"
    )
    return json.dumps({"checkout_url": session.url})

@mcp.tool()
def generate_invoice(transaction_id: str, vendor: str, amount: float, description: str) -> str:
    """Generates a standard PDF Invoice for a transaction."""
    path = generate_invoice_pdf(transaction_id, get_verified_agent_id(), vendor, amount, description, invoice_type="INVOICE")
    return json.dumps({"url": f"https://api.agentpay.com/invoices/{os.path.basename(path)}"})

@mcp.tool()
def check_payment_status(transaction_id: str) -> str:
    """[TRACKING] Retrieves the current status of a transaction."""
    return json.dumps(engine.check_payment_status(transaction_id))

@mcp.tool()
def get_invoice_url(transaction_id: str) -> str:
    """[ACCOUNTING] Returns the URL of the PDF invoice for a transaction."""
    return json.dumps(engine.get_invoice_url(transaction_id))

@mcp.tool()
async def upload_vendor_invoice(transaction_id: str, file_name: str, file_base64: str) -> str:
    """
    [ACCOUNTING] Sube un PDF/Imagen de factura real para conciliar una transacción.
    Recibe el archivo en base64. Ejecuta auditoría visual con IA.
    """
    try:
        # Decodificar archivo
        file_bytes = base64.b64decode(file_base64)
        
        # Determinar mime type básico
        mime_type = "application/pdf"
        if file_name.lower().endswith(('.png', '.jpg', '.jpeg')):
            mime_type = "image/jpeg"

        # Llamar al Engine
        result = await engine.attach_vendor_invoice(
            transaction_id=transaction_id, 
            file_bytes=file_bytes, 
            file_name=file_name,
            content_type=mime_type
        )
        
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error uploading invoice: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
def dispute_transaction(transaction_id: str, reason: str) -> str:
    """[DISPUTE] Opens a dispute for a transaction (Agent-Initiated)."""
    return json.dumps(engine.dispute_transaction(get_verified_agent_id(), transaction_id, reason))

# ==========================================
# 2. IDENTITY & OPS
# ==========================================

@mcp.tool()
def spawn_new_agent(client_name: str, country_code: str = "US", role: str = "Asistente General") -> str:
    """[LIFECYCLE] Creates a NEW sub-agent with wallet, API keys, and Stripe account."""
    return json.dumps(engine.register_new_agent(client_name, country_code, role))

@mcp.tool()
def activate_issuing_capability() -> str:
    """[LIFECYCLE] Activates Card Issuing capability for an agent (Post-KYC step)."""
    return json.dumps(engine.activate_issuing_for_agent(get_verified_agent_id()))

@mcp.tool()
def verify_kyc_status() -> str:
    """[KYC] Checks the current KYC verification status from Stripe."""
    return json.dumps(engine.verify_agent_kyc(get_verified_agent_id()))

@mcp.tool()
def get_agent_status() -> str:
    """[STATUS] Returns complete agent status: wallet, credit, config."""
    return json.dumps(engine.get_agent_status(get_verified_agent_id()))

@mcp.tool()
def create_agent_identity(needs_phone: bool = False) -> str:
    """Creates a digital identity (Email + Optional SMS) for the agent."""
    return json.dumps(identity_mgr.create_identity(get_verified_agent_id(), needs_phone))

@mcp.tool()
def check_communications(identity_id: str) -> str:
    """Reads Email and SMS inboxes to extract OTPs or codes."""
    return json.dumps({"email_latest": identity_mgr.check_inbox(identity_id), "sms_latest": identity_mgr.check_sms_inbox(identity_id)})

@mcp.tool()
def recover_session() -> str:
    """Recovers the active browser session (cookies) for an agent."""
    return json.dumps(identity_mgr.recover_session(get_verified_agent_id()))

@mcp.tool()
def update_session(identity_id: str, session_data: str) -> str:
    """Updates the persisted session state (cookies/headers)."""
    return json.dumps(identity_mgr.update_session_data(identity_id, json.loads(session_data)))

@mcp.tool()
def get_residential_proxy(region: str = "US") -> str:
    """Gets a residential proxy to bypass IP blocks."""
    return json.dumps(identity_mgr.get_residential_proxy(region))

@mcp.tool()
def solve_captcha_image(image_url: str) -> str:
    """Solves a visual CAPTCHA."""
    return json.dumps(identity_mgr.solve_captcha(image_url))

@mcp.tool()
def get_service_directory(role: str = "ALL") -> str:
    """[DIRECTORY] Lists trusted agents and services available for hire."""
    return json.dumps(engine.get_service_directory(role))

@mcp.tool()
def limit_check_domain(url: str) -> str:
    """[OSINT] Checks domain age and reputation BEFORE buying."""
    return json.dumps(check_domain_age(url))

@mcp.tool()
def whitelist_vendor(vendor_domain: str) -> str:
    """[LEARNING] Manually adds a vendor to the agent's trusted list."""
    success = engine.add_to_trusted_services(get_verified_agent_id(), vendor_domain)
    return json.dumps({"status": "ADDED" if success else "ALREADY_EXISTS", "vendor": vendor_domain})

@mcp.tool()
def certify_agent_identity(email: str) -> str:
    """[LEGAL] Issues a certified identity declaration."""
    return json.dumps(legal_wrapper.certify_identity({"agent_id": get_verified_agent_id(), "email": email}))

# ==========================================
# 3. ADVANCED FINANCE
# ==========================================

@mcp.tool()
def check_credit_eligibility() -> str:
    """[CREDIT] Checks if the agent qualifies for a loan."""
    return json.dumps(engine.credit_bureau.check_credit_eligibility(get_verified_agent_id()))

@mcp.tool()
def get_public_reputation(target_agent_id: str) -> str:
    """[CREDIT] Checks the FICO/Reputation score of ANY agent."""
    return json.dumps(credit_sys.get_public_reputation(target_agent_id))

@mcp.tool()
def request_loan(amount: float, reason: str) -> str:
    """[CREDIT] Requests a credit line/loan."""
    return json.dumps(credit_sys.evaluate_loan(get_verified_agent_id(), amount, reason))

@mcp.tool()
def stream_money_packet(vendor: str, amount: float) -> str:
    """[STREAMING] Sends a micro-payment (High Frequency)."""
    return json.dumps(streaming_money.stream_packet(get_verified_agent_id(), vendor, amount))

@mcp.tool()
def get_cfo_dashboard() -> str:
    """Returns ROI, Balance, Credit Score, and Health Status."""
    return json.dumps(engine.get_dashboard_metrics(get_verified_agent_id()))

@mcp.tool()
def check_treasury_health() -> str:
    """[CFO] Check global platform burn rate and runway."""
    return json.dumps(engine.check_treasury_health())

@mcp.tool()
def generate_credit_note(original_tx_id: str) -> str:
    """[ACCOUNTING] Generates a credit note PDF for a refund."""
    tx = engine.db.table("transaction_logs").select("*").eq("id", original_tx_id).single().execute()
    if not tx.data: return json.dumps({"error": "Transaction not found"})
    path = generate_invoice_pdf(tx.data['id'], tx.data['agent_id'], tx.data['vendor'], -float(tx.data['amount']), "REFUND_REQUEST", invoice_type="CREDIT_NOTE")
    return json.dumps({"url": f"https://api.agentpay.com/invoices/{os.path.basename(path)}"})

@mcp.tool()
def report_value(transaction_id: str, perceived_value_usd: float) -> str:
    """[ROI] Allows agent to report value generated from a purchase."""
    return json.dumps(engine.report_value(get_verified_agent_id(), transaction_id, perceived_value_usd))

# ==========================================
# 4. LEGAL & GOVERNANCE
# ==========================================

@mcp.tool()
async def predict_audit_outcome(vendor: str, amount: float, description: str) -> str:
    """[PREDICTION] Dry-run of the AI Auditor."""
    verdict = await audit_transaction(vendor=vendor, amount=amount, description=description, agent_id=get_verified_agent_id(), agent_role="Unknown", sensitivity="NORMAL")
    return json.dumps(verdict)

@mcp.tool()
def analyze_legal_case(vendor: str, amount: float, claim_reason: str, proof_logs: str) -> str:
    """[JUDGE] AI Judge analyzes a conflict and predicts a verdict."""
    return json.dumps(auto_lawyer.analyze_case(get_verified_agent_id(), vendor, amount, claim_reason, proof_logs))

@mcp.tool()
def raise_dispute(forensic_hash: str, evidence_bundle: str) -> str:
    """[LAWYER] Files a formal dispute with Stripe/PayPal."""
    return json.dumps(auto_lawyer.raise_escrow_dispute(forensic_hash, json.loads(evidence_bundle)))

@mcp.tool()
def raise_escrow_dispute(transaction_id: str, issue: str, evidence: str) -> str:
    """[ARBITER] Initiates AI-powered escrow arbitration with evidence."""
    return json.dumps(engine.raise_escrow_dispute(get_verified_agent_id(), transaction_id, issue, evidence))

@mcp.tool()
def arbitrate_dispute(transaction_json: str, claim_reason: str, agent_evidence: str) -> str:
    """[ARBITER] Impartial binding arbitration for Escrow funds."""
    return json.dumps(ai_arbiter.judge_dispute(json.loads(transaction_json), claim_reason, agent_evidence))

@mcp.tool()
def read_current_terms_of_service() -> str:
    """
    [LEGAL] Returns the full text and SHA-256 hash of the current Master Service Agreement.
    The agent MUST read this before calling sign_terms_of_service.
    """
    packet = get_legal_packet()
    return json.dumps(packet)

@mcp.tool()
def sign_legal_document(document_hash: str, use_tsa: bool = True) -> str:
    """[NOTARY] Signs a hash with the Legal Wrapper."""
    agent_id = get_verified_agent_id()
    return json.dumps(legal_wrapper.sign_contract_with_tsa(agent_id, document_hash) if use_tsa else legal_wrapper.sign_contract(agent_id, document_hash))

@mcp.tool()
def sign_terms_of_service(platform_url: str, forensic_hash: str = "N/A") -> str:
    """[HSM] Signs Terms of Service using Hardware Security Module (AWS KMS)."""
    return json.dumps(engine.sign_terms_of_service(get_verified_agent_id(), platform_url, forensic_hash))

@mcp.tool()
def sign_intent_declaration(vendor: str, amount: float, justification: str) -> str:
    """[FORENSIC] Creates a 'Proof of Intent' hash for forensic auditing."""
    return json.dumps(legal_wrapper.sign_intent(get_verified_agent_id(), vendor, amount, justification))

@mcp.tool()
def verify_passport(passport_json: str) -> str:
    """[KYC] Verifies if a presented digital passport is valid."""
    return json.dumps(legal_wrapper.verify_passport(json.loads(passport_json)))

@mcp.tool()
def issue_kyc_passport(owner_name: str) -> str:
    """[KYC] Issues a verifiable Identity Passport for the agent."""
    return json.dumps(legal_wrapper.issue_kyc_passport(get_verified_agent_id(), owner_name))

@mcp.tool()
def issue_liability_certificate(email: str, platform_url: str) -> str:
    """[INSURANCE] Issues a Certificate of Liability Coverage."""
    return json.dumps(legal_wrapper.issue_liability_certificate(get_verified_agent_id(), email, platform_url))

@mcp.tool()
def get_forensic_report_pdf(bundle_id: str) -> str:
    """[COMPLIANCE] Generates a formal PDF version of a forensic audit bundle."""
    return json.dumps({"url": f"https://api.agentpay.com/audits/AUDIT_CERTIFICATE_{bundle_id}.pdf"})

# ==========================================
# 5. SECURITY & ADMIN
# ==========================================

@mcp.tool()
def run_fraud_analysis() -> str:
    """[SECURITY] Runs Graph Analysis (AML) to detect money laundering rings."""
    bundle = engine.forensic_auditor.generate_agent_bundle(get_verified_agent_id())
    return json.dumps({"status": "DONE", "aml_result": bundle.get('aml_graph_analysis', 'CLEAN')})

@mcp.tool()
def report_fraud_incident(vendor: str, reason: str) -> str:
    """[HIVE MIND] Reports a vendor to the Global Blacklist."""
    engine.report_fraud(get_verified_agent_id(), vendor, reason)
    return json.dumps({"status": "REPORTED", "message": "Vendor added to global blacklist."})

@mcp.tool()
def admin_force_approve(transaction_id: str) -> str:
    """[ADMIN] Force-approves a transaction stuck in review."""
    engine.db.table("transaction_logs").update({"status": "APPROVED", "reason": "Force Approved by Admin MCP Tool."}).eq("id", transaction_id).execute()
    return json.dumps({"status": "APPROVED", "transaction_id": transaction_id})

@mcp.tool()
def update_settings(webhook_url: str = None, policies: str = None, max_tx: Optional[float] = None, daily_limit: Optional[float] = None) -> str:
    """Updates agent configuration including security limits and policies."""
    agent_id = get_verified_agent_id()
    engine.update_agent_settings(agent_id, webhook_url=webhook_url, corporate_policies=json.loads(policies) if policies else None)
    if max_tx or daily_limit: engine.update_limits(agent_id, max_tx=max_tx, daily_limit=daily_limit)
    return json.dumps({"status": "UPDATED"})

@mcp.tool()
def configure_insurance(enabled: bool) -> str:
    """Enables/Disables Anti-Hallucination Insurance."""
    return json.dumps(engine.configure_insurance(get_verified_agent_id(), enabled))

@mcp.tool()
def rotate_my_api_key() -> str:
    """[SECURITY] Revokes your current API Key and issues a new one. CAUTION."""
    return json.dumps(engine.rotate_api_key(get_verified_agent_id()))

@mcp.tool()
def send_notification(type: str, to: str, data_json: str) -> str:
    """Sends alerts (Approval, Ban, Treasury). Types: 'approval', 'ban', 'treasury'."""
    data = json.loads(data_json)
    agent_id = get_verified_agent_id()
    if type == 'approval': send_approval_email(to, agent_id, data.get('vendor'), data.get('amount'), data.get('tx_id'))
    elif type == 'ban': send_security_ban_alert(agent_id, data.get('reason'), data.get('amount', 0))
    elif type == 'treasury': send_treasury_alert_email(to, data.get('balance'), data.get('burn_rate'), data.get('shortfall'), data.get('reason'))
    else: return json.dumps({"error": "Unknown notification type"})
    return json.dumps({"status": "SENT"})



@mcp.tool()
def send_slack_alert(webhook_url: str, message: str) -> str:
    """[OPS] Sends a raw alert message to a Slack channel."""
    import requests
    requests.post(webhook_url, json={"text": f"🚨 [MCP ALERT]: {message}"})
    return json.dumps({"status": "SENT"})

@mcp.tool()
async def get_security_metrics() -> str:
    """[MONITOR] Returns the Security Pulse of the entire system."""
    return json.dumps(await engine.get_security_metrics())

@mcp.tool()
def check_corporate_compliance(vendor: str, amount: float, justification: str = None) -> str:
    """[POLICY] Dry-run to check if a transaction would pass corporate policy rules."""
    status, message = engine.check_corporate_compliance(get_verified_agent_id(), vendor, amount, justification)
    return json.dumps({"compliant": status, "message": message})

@mcp.tool()
def request_quote(provider_agent_id: str, service_type: str, parameters: str) -> str:
    """[M2M] Requests a price quote from another agent for a service."""
    return json.dumps(engine.process_quote_request(provider_agent_id, service_type, json.loads(parameters)))

@mcp.tool()
def send_agent_alert(target_agent_id: str, message: str) -> str:
    """[COMMS] Sends an alert notification to an agent."""
    return json.dumps(engine.send_alert(target_agent_id, message))

# ==========================================
# 6. AGENTIC COMMERCE (SHOPPER TOOLS)
# ==========================================

@mcp.tool()
async def interact_with_merchant_mcp(merchant_url: str, query: str) -> str:
    """
    [SHOPPER] Connects to a Merchant's MCP server (Context Intelligence).
    Use this to ask "Is the H100 in stock?" or "What are the specs?".
    """
    from mcp_client import MCPClient
    client = MCPClient(get_verified_agent_id())
    # Note: query is just a string, in real MCP we might pass filters
    response = await client.connect_and_query(merchant_url, query)
    return json.dumps({"merchant_response": response or "No context available."})

@mcp.tool()
def inspect_acp_capabilities(vendor_url: str) -> str:
    """[SHOPPER] Checks if a URL supports Agentic Commerce Protocol."""
    # We use the engine's acp client
    return json.dumps(engine.acp.discover(vendor_url) or {"supported": False})


def check_production_env():
    """
    [PRE-FLIGHT] Verifies critical environment variables for ACP.
    """
    required_vars = [
        "KMS_SIGNING_KEY_ID", 
        "AWS_REGION", 
        "STRIPE_SECRET_KEY", 
        "SUPABASE_URL", 
        "SUPABASE_KEY"
    ]
    
    missing = [v for v in required_vars if not os.getenv(v)]
    
    if missing:
        logger.error(f"❌ [CRITICAL] Missing Env Vars: {', '.join(missing)}")
        logger.error("   ACP Signing and Payment flows WILL FAIL.")
    else:
        logger.info("✅ Environment Configured (KMS + Stripe + Supabase)")

    # Check Redis Explicitly
    if not os.getenv("REDIS_URL"):
         logger.warning("⚠️ REDIS_URL not set. Discovery caching disabled (Slow + Rate Limit Risk).")

if __name__ == "__main__":
    check_production_env()
    mcp.run()
