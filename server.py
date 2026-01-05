"""
AgentPay MCP Server - God Mode (Secured with Middleware)
Using FastMCP 2.9+ native middleware for authentication
"""
from mcp.server.fastmcp import FastMCP
import sentry_sdk
import json
import os
import stripe
import time
from datetime import datetime
from typing import Optional
from loguru import logger

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

# Initialize Subsystems
engine = UniversalEngine()
identity_mgr = IdentityManager(engine.db)
credit_sys = CreditBureau(engine.db)
streaming_money = StreamingMoney(engine.db)
legal_wrapper = LegalWrapper()
auto_lawyer = AutoLawyer()
ai_arbiter = AIArbiter()
forensic_auditor = ForensicAuditor(engine.db)

# Rate limiting config
RATE_LIMIT_RPM = int(os.getenv("MCP_RATE_LIMIT_RPM", "60"))

# ==========================================
# SECURITY MIDDLEWARE (FastMCP 2.9+ Native)
# ==========================================

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
    """Audit log to Supabase."""
    try:
        engine.db.table("mcp_audit_log").insert({
            "agent_id": agent_id,
            "tool_name": tool_name,
            "parameters": json.dumps(params)[:2000],
            "result_status": status,
            "timestamp": datetime.utcnow().isoformat()
        }).execute()
    except Exception as e:
        logger.warning(f"Audit log failed: {e}")

async def auth_middleware(request, call_next):
    """
    FastMCP Native Middleware - Intercepts ALL tool calls.
    Validates api_key, applies rate limiting, logs everything.
    """
    # Extract api_key from request arguments
    args = request.arguments or {}
    api_key = args.get("api_key")
    
    # 1. Auth Check
    if not api_key:
        return {"error": "UNAUTHORIZED", "message": "api_key required", "code": 401}
    
    agent_id = engine.verify_agent_credentials(api_key)
    if not agent_id:
        _log_mcp_call("UNKNOWN", request.name, args, "AUTH_FAILED")
        return {"error": "UNAUTHORIZED", "message": "Invalid api_key", "code": 401}
    
    # 2. Rate Limit
    if not _check_rate_limit(agent_id):
        _log_mcp_call(agent_id, request.name, args, "RATE_LIMITED")
        return {"error": "RATE_LIMITED", "message": f"Exceeded {RATE_LIMIT_RPM} RPM", "code": 429}
    
    # 3. Inject verified agent_id into request
    request.arguments["_verified_agent_id"] = agent_id
    sentry_sdk.set_user({"id": agent_id})
    
    # 4. Execute tool
    try:
        result = await call_next(request)
        _log_mcp_call(agent_id, request.name, args, "OK")
        return result
    except Exception as e:
        # Log full error to Sentry for debugging (NOT exposed to user)
        sentry_sdk.capture_exception(e)
        _log_mcp_call(agent_id, request.name, args, f"ERROR: {type(e).__name__}")
        # Return generic error message (no stack trace leakage)
        return {"error": "INTERNAL_ERROR", "message": "An unexpected error occurred. Please try again.", "code": 500}

# Initialize Server WITH Middleware
mcp = FastMCP(
    "AgentPay God Mode",
    dependencies=["stripe", "supabase", "networkx", "boto3", "openai"]
)

# Register the auth middleware
mcp.add_middleware(auth_middleware)

# Helper to get verified agent_id from middleware injection
def get_agent_id(kwargs: dict) -> str:
    """Extract verified agent_id injected by middleware."""
    return kwargs.pop("_verified_agent_id", kwargs.get("agent_id", ""))

# ==========================================
# 1. CORE FINANCIAL
# ==========================================

@mcp.tool()
def pay_vendor(vendor: str, amount: float, description: str, justification: str = None, api_key: str = None, **kwargs) -> str:
    """Executes a standard B2B payment. Returns status and receipt."""
    agent_id = get_agent_id(kwargs)
    req = TransactionRequest(agent_id=agent_id, vendor=vendor, amount=amount, description=description, justification=justification)
    result = engine.evaluate(req)
    return json.dumps({"success": result.authorized, "status": result.status, "tx_id": result.transaction_id, "reason": result.reason, "receipt": result.forensic_bundle_url})

@mcp.tool()
def process_procurement(vendor: str, amount: float, items: list[str], description: str, api_key: str = None, **kwargs) -> str:
    """[COMPLEX] Executes a procurement order with multiple line items."""
    return json.dumps(engine.process_procurement(get_agent_id(kwargs), vendor, amount, items, description))

@mcp.tool()
def issue_virtual_card(amount: float, vendor: str, mcc_category: str = 'services', api_key: str = None, **kwargs) -> str:
    """[ISSUING] Creates a one-time virtual card for a specific vendor."""
    return json.dumps(engine._issue_virtual_card(get_agent_id(kwargs), amount, vendor, mcc_category))

@mcp.tool()
def scan_qr_and_pay(qr_url: str, api_key: str = None, **kwargs) -> str:
    """[VISION] Reads a Stripe/Payment QR URL and pays it automatically."""
    return json.dumps(engine.scan_and_pay_qr(get_agent_id(kwargs), qr_url))

@mcp.tool()
def create_escrow(vendor: str, amount: float, description: str, api_key: str = None, **kwargs) -> str:
    """[ESCROW] Creates a transaction where funds are held until confirmation."""
    return json.dumps(engine.create_escrow_transaction(get_agent_id(kwargs), vendor, amount, description))

@mcp.tool()
def release_escrow(transaction_id: str, api_key: str = None, **kwargs) -> str:
    """[ESCROW] Confirms delivery and releases funds to vendor."""
    return json.dumps(engine.confirm_delivery(get_agent_id(kwargs), transaction_id))

@mcp.tool()
def create_balance_topup(amount: float, api_key: str = None, **kwargs) -> str:
    """Generates a Stripe Checkout link for a human to add funds to the agent wallet."""
    agent_id = get_agent_id(kwargs)
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{'price_data': {'currency': 'usd', 'product_data': {'name': f'Agent Topup ({agent_id})'}, 'unit_amount': int(amount * 100)}, 'quantity': 1}],
        mode='payment', metadata={'agent_id': agent_id, 'type': 'TOPUP'},
        success_url="https://agentpay.ai/success?session_id={CHECKOUT_SESSION_ID}", cancel_url="https://agentpay.ai/cancel"
    )
    return json.dumps({"checkout_url": session.url})

@mcp.tool()
def generate_invoice(transaction_id: str, vendor: str, amount: float, description: str, api_key: str = None, **kwargs) -> str:
    """Generates a standard PDF Invoice for a transaction."""
    path = generate_invoice_pdf(transaction_id, get_agent_id(kwargs), vendor, amount, description, invoice_type="INVOICE")
    return json.dumps({"url": f"https://api.agentpay.com/invoices/{os.path.basename(path)}"})

@mcp.tool()
def check_payment_status(transaction_id: str, api_key: str = None, **kwargs) -> str:
    """[TRACKING] Retrieves the current status of a transaction."""
    return json.dumps(engine.check_payment_status(transaction_id))

@mcp.tool()
def get_invoice_url(transaction_id: str, api_key: str = None, **kwargs) -> str:
    """[ACCOUNTING] Returns the URL of the PDF invoice for a transaction."""
    return json.dumps(engine.get_invoice_url(transaction_id))

@mcp.tool()
def dispute_transaction(transaction_id: str, reason: str, api_key: str = None, **kwargs) -> str:
    """[DISPUTE] Opens a dispute for a transaction (Agent-Initiated)."""
    return json.dumps(engine.dispute_transaction(get_agent_id(kwargs), transaction_id, reason))

# ==========================================
# 2. IDENTITY & OPS
# ==========================================

@mcp.tool()
def spawn_new_agent(client_name: str, country_code: str = "US", role: str = "Asistente General", api_key: str = None, **kwargs) -> str:
    """[LIFECYCLE] Creates a NEW sub-agent with wallet, API keys, and Stripe account."""
    return json.dumps(engine.register_new_agent(client_name, country_code, role))

@mcp.tool()
def activate_issuing_capability(api_key: str = None, **kwargs) -> str:
    """[LIFECYCLE] Activates Card Issuing capability for an agent (Post-KYC step)."""
    return json.dumps(engine.activate_issuing_for_agent(get_agent_id(kwargs)))

@mcp.tool()
def verify_kyc_status(api_key: str = None, **kwargs) -> str:
    """[KYC] Checks the current KYC verification status from Stripe."""
    return json.dumps(engine.verify_agent_kyc(get_agent_id(kwargs)))

@mcp.tool()
def get_agent_status(api_key: str = None, **kwargs) -> str:
    """[STATUS] Returns complete agent status: wallet, credit, config."""
    return json.dumps(engine.get_agent_status(get_agent_id(kwargs)))

@mcp.tool()
def create_agent_identity(needs_phone: bool = False, api_key: str = None, **kwargs) -> str:
    """Creates a digital identity (Email + Optional SMS) for the agent."""
    return json.dumps(identity_mgr.create_identity(get_agent_id(kwargs), needs_phone))

@mcp.tool()
def check_communications(identity_id: str, api_key: str = None, **kwargs) -> str:
    """Reads Email and SMS inboxes to extract OTPs or codes."""
    return json.dumps({"email_latest": identity_mgr.check_inbox(identity_id), "sms_latest": identity_mgr.check_sms_inbox(identity_id)})

@mcp.tool()
def recover_session(api_key: str = None, **kwargs) -> str:
    """Recovers the active browser session (cookies) for an agent."""
    return json.dumps(identity_mgr.recover_session(get_agent_id(kwargs)))

@mcp.tool()
def update_session(identity_id: str, session_data: str, api_key: str = None, **kwargs) -> str:
    """Updates the persisted session state (cookies/headers)."""
    return json.dumps(identity_mgr.update_session_data(identity_id, json.loads(session_data)))

@mcp.tool()
def get_residential_proxy(region: str = "US", api_key: str = None, **kwargs) -> str:
    """Gets a residential proxy to bypass IP blocks."""
    return json.dumps(identity_mgr.get_residential_proxy(region))

@mcp.tool()
def solve_captcha_image(image_url: str, api_key: str = None, **kwargs) -> str:
    """Solves a visual CAPTCHA."""
    return json.dumps(identity_mgr.solve_captcha(image_url))

@mcp.tool()
def get_service_directory(role: str = "ALL", api_key: str = None, **kwargs) -> str:
    """[DIRECTORY] Lists trusted agents and services available for hire."""
    return json.dumps(engine.get_service_directory(role))

@mcp.tool()
def limit_check_domain(url: str, api_key: str = None, **kwargs) -> str:
    """[OSINT] Checks domain age and reputation BEFORE buying."""
    return json.dumps(check_domain_age(url))

@mcp.tool()
def whitelist_vendor(vendor_domain: str, api_key: str = None, **kwargs) -> str:
    """[LEARNING] Manually adds a vendor to the agent's trusted list."""
    success = engine.add_to_trusted_services(get_agent_id(kwargs), vendor_domain)
    return json.dumps({"status": "ADDED" if success else "ALREADY_EXISTS", "vendor": vendor_domain})

@mcp.tool()
def certify_agent_identity(email: str, api_key: str = None, **kwargs) -> str:
    """[LEGAL] Issues a certified identity declaration."""
    return json.dumps(legal_wrapper.certify_identity({"agent_id": get_agent_id(kwargs), "email": email}))

# ==========================================
# 3. ADVANCED FINANCE
# ==========================================

@mcp.tool()
def check_credit_eligibility(api_key: str = None, **kwargs) -> str:
    """[CREDIT] Checks if the agent qualifies for a loan."""
    return json.dumps(engine.credit_bureau.check_credit_eligibility(get_agent_id(kwargs)))

@mcp.tool()
def get_public_reputation(target_agent_id: str, api_key: str = None, **kwargs) -> str:
    """[CREDIT] Checks the FICO/Reputation score of ANY agent."""
    return json.dumps(credit_sys.get_public_reputation(target_agent_id))

@mcp.tool()
def request_loan(amount: float, reason: str, api_key: str = None, **kwargs) -> str:
    """[CREDIT] Requests a credit line/loan."""
    return json.dumps(credit_sys.evaluate_loan(get_agent_id(kwargs), amount, reason))

@mcp.tool()
def stream_money_packet(vendor: str, amount: float, api_key: str = None, **kwargs) -> str:
    """[STREAMING] Sends a micro-payment (High Frequency)."""
    return json.dumps(streaming_money.stream_packet(get_agent_id(kwargs), vendor, amount))

@mcp.tool()
def get_cfo_dashboard(api_key: str = None, **kwargs) -> str:
    """Returns ROI, Balance, Credit Score, and Health Status."""
    return json.dumps(engine.get_dashboard_metrics(get_agent_id(kwargs)))

@mcp.tool()
def check_treasury_health(api_key: str = None, **kwargs) -> str:
    """[CFO] Check global platform burn rate and runway."""
    return json.dumps(engine.check_treasury_health())

@mcp.tool()
def generate_credit_note(original_tx_id: str, api_key: str = None, **kwargs) -> str:
    """[ACCOUNTING] Generates a credit note PDF for a refund."""
    tx = engine.db.table("transaction_logs").select("*").eq("id", original_tx_id).single().execute()
    if not tx.data: return json.dumps({"error": "Transaction not found"})
    path = generate_invoice_pdf(tx.data['id'], tx.data['agent_id'], tx.data['vendor'], -float(tx.data['amount']), "REFUND_REQUEST", invoice_type="CREDIT_NOTE")
    return json.dumps({"url": f"https://api.agentpay.com/invoices/{os.path.basename(path)}"})

@mcp.tool()
def report_value(transaction_id: str, perceived_value_usd: float, api_key: str = None, **kwargs) -> str:
    """[ROI] Allows agent to report value generated from a purchase."""
    return json.dumps(engine.report_value(get_agent_id(kwargs), transaction_id, perceived_value_usd))

# ==========================================
# 4. LEGAL & GOVERNANCE
# ==========================================

@mcp.tool()
async def predict_audit_outcome(vendor: str, amount: float, description: str, api_key: str = None, **kwargs) -> str:
    """[PREDICTION] Dry-run of the AI Auditor."""
    verdict = await audit_transaction(vendor=vendor, amount=amount, description=description, agent_id=get_agent_id(kwargs), agent_role="Unknown", sensitivity="NORMAL")
    return json.dumps(verdict)

@mcp.tool()
def analyze_legal_case(vendor: str, amount: float, claim_reason: str, proof_logs: str, api_key: str = None, **kwargs) -> str:
    """[JUDGE] AI Judge analyzes a conflict and predicts a verdict."""
    return json.dumps(auto_lawyer.analyze_case(get_agent_id(kwargs), vendor, amount, claim_reason, proof_logs))

@mcp.tool()
def raise_dispute(forensic_hash: str, evidence_bundle: str, api_key: str = None, **kwargs) -> str:
    """[LAWYER] Files a formal dispute with Stripe/PayPal."""
    return json.dumps(auto_lawyer.raise_escrow_dispute(forensic_hash, json.loads(evidence_bundle)))

@mcp.tool()
def raise_escrow_dispute(transaction_id: str, issue: str, evidence: str, api_key: str = None, **kwargs) -> str:
    """[ARBITER] Initiates AI-powered escrow arbitration with evidence."""
    return json.dumps(engine.raise_escrow_dispute(get_agent_id(kwargs), transaction_id, issue, evidence))

@mcp.tool()
def arbitrate_dispute(transaction_json: str, claim_reason: str, agent_evidence: str, api_key: str = None, **kwargs) -> str:
    """[ARBITER] Impartial binding arbitration for Escrow funds."""
    return json.dumps(ai_arbiter.judge_dispute(json.loads(transaction_json), claim_reason, agent_evidence))

@mcp.tool()
def sign_legal_document(document_hash: str, use_tsa: bool = True, api_key: str = None, **kwargs) -> str:
    """[NOTARY] Signs a hash with the Legal Wrapper."""
    agent_id = get_agent_id(kwargs)
    return json.dumps(legal_wrapper.sign_contract_with_tsa(agent_id, document_hash) if use_tsa else legal_wrapper.sign_contract(agent_id, document_hash))

@mcp.tool()
def sign_terms_of_service(platform_url: str, forensic_hash: str = "N/A", api_key: str = None, **kwargs) -> str:
    """[HSM] Signs Terms of Service using Hardware Security Module (AWS KMS)."""
    return json.dumps(engine.sign_terms_of_service(get_agent_id(kwargs), platform_url, forensic_hash))

@mcp.tool()
def sign_intent_declaration(vendor: str, amount: float, justification: str, api_key: str = None, **kwargs) -> str:
    """[FORENSIC] Creates a 'Proof of Intent' hash for forensic auditing."""
    return json.dumps(legal_wrapper.sign_intent(get_agent_id(kwargs), vendor, amount, justification))

@mcp.tool()
def verify_passport(passport_json: str, api_key: str = None, **kwargs) -> str:
    """[KYC] Verifies if a presented digital passport is valid."""
    return json.dumps(legal_wrapper.verify_passport(json.loads(passport_json)))

@mcp.tool()
def issue_kyc_passport(owner_name: str, api_key: str = None, **kwargs) -> str:
    """[KYC] Issues a verifiable Identity Passport for the agent."""
    return json.dumps(legal_wrapper.issue_kyc_passport(get_agent_id(kwargs), owner_name))

@mcp.tool()
def issue_liability_certificate(email: str, platform_url: str, api_key: str = None, **kwargs) -> str:
    """[INSURANCE] Issues a Certificate of Liability Coverage."""
    return json.dumps(legal_wrapper.issue_liability_certificate(get_agent_id(kwargs), email, platform_url))

@mcp.tool()
def get_forensic_report_pdf(bundle_id: str, api_key: str = None, **kwargs) -> str:
    """[COMPLIANCE] Generates a formal PDF version of a forensic audit bundle."""
    return json.dumps({"url": f"https://api.agentpay.com/audits/AUDIT_CERTIFICATE_{bundle_id}.pdf"})

# ==========================================
# 5. SECURITY & ADMIN
# ==========================================

@mcp.tool()
def run_fraud_analysis(api_key: str = None, **kwargs) -> str:
    """[SECURITY] Runs Graph Analysis (AML) to detect money laundering rings."""
    bundle = engine.forensic_auditor.generate_agent_bundle(get_agent_id(kwargs))
    return json.dumps({"status": "DONE", "aml_result": bundle.get('aml_graph_analysis', 'CLEAN')})

@mcp.tool()
def report_fraud_incident(vendor: str, reason: str, api_key: str = None, **kwargs) -> str:
    """[HIVE MIND] Reports a vendor to the Global Blacklist."""
    engine.report_fraud(get_agent_id(kwargs), vendor, reason)
    return json.dumps({"status": "REPORTED", "message": "Vendor added to global blacklist."})

@mcp.tool()
def admin_force_approve(transaction_id: str, api_key: str = None, **kwargs) -> str:
    """[ADMIN] Force-approves a transaction stuck in review."""
    engine.db.table("transaction_logs").update({"status": "APPROVED", "reason": "Force Approved by Admin MCP Tool."}).eq("id", transaction_id).execute()
    return json.dumps({"status": "APPROVED", "transaction_id": transaction_id})

@mcp.tool()
def update_settings(webhook_url: str = None, policies: str = None, max_tx: Optional[float] = None, daily_limit: Optional[float] = None, api_key: str = None, **kwargs) -> str:
    """Updates agent configuration including security limits and policies."""
    agent_id = get_agent_id(kwargs)
    engine.update_agent_settings(agent_id, webhook_url=webhook_url, corporate_policies=json.loads(policies) if policies else None)
    if max_tx or daily_limit: engine.update_limits(agent_id, max_tx=max_tx, daily_limit=daily_limit)
    return json.dumps({"status": "UPDATED"})

@mcp.tool()
def configure_insurance(enabled: bool, api_key: str = None, **kwargs) -> str:
    """Enables/Disables Anti-Hallucination Insurance."""
    return json.dumps(engine.configure_insurance(get_agent_id(kwargs), enabled))

@mcp.tool()
def send_notification(type: str, to: str, data_json: str, api_key: str = None, **kwargs) -> str:
    """Sends alerts (Approval, Ban, Treasury). Types: 'approval', 'ban', 'treasury'."""
    data = json.loads(data_json)
    agent_id = get_agent_id(kwargs)
    if type == 'approval': send_approval_email(to, agent_id, data.get('vendor'), data.get('amount'), data.get('tx_id'))
    elif type == 'ban': send_security_ban_alert(agent_id, data.get('reason'), data.get('amount', 0))
    elif type == 'treasury': send_treasury_alert_email(to, data.get('balance'), data.get('burn_rate'), data.get('shortfall'), data.get('reason'))
    else: return json.dumps({"error": "Unknown notification type"})
    return json.dumps({"status": "SENT"})

@mcp.tool()
def trigger_webhook_test(url: str, event: str, data: str, api_key: str = None, **kwargs) -> str:
    """[DEV] Fires a test webhook used for integration testing."""
    send_webhook(url, event, json.loads(data))
    return json.dumps({"status": "TRIGGERED"})

@mcp.tool()
def send_slack_alert(webhook_url: str, message: str, api_key: str = None, **kwargs) -> str:
    """[OPS] Sends a raw alert message to a Slack channel."""
    import requests
    requests.post(webhook_url, json={"text": f"🚨 [MCP ALERT]: {message}"})
    return json.dumps({"status": "SENT"})

@mcp.tool()
async def get_security_metrics(api_key: str = None, **kwargs) -> str:
    """[MONITOR] Returns the Security Pulse of the entire system."""
    return json.dumps(await engine.get_security_metrics())

@mcp.tool()
def check_corporate_compliance(vendor: str, amount: float, justification: str = None, api_key: str = None, **kwargs) -> str:
    """[POLICY] Dry-run to check if a transaction would pass corporate policy rules."""
    status, message = engine.check_corporate_compliance(get_agent_id(kwargs), vendor, amount, justification)
    return json.dumps({"compliant": status, "message": message})

@mcp.tool()
def request_quote(provider_agent_id: str, service_type: str, parameters: str, api_key: str = None, **kwargs) -> str:
    """[M2M] Requests a price quote from another agent for a service."""
    return json.dumps(engine.process_quote_request(provider_agent_id, service_type, json.loads(parameters)))

@mcp.tool()
def send_agent_alert(target_agent_id: str, message: str, api_key: str = None, **kwargs) -> str:
    """[COMMS] Sends an alert notification to an agent."""
    return json.dumps(engine.send_alert(target_agent_id, message))

if __name__ == "__main__":
    mcp.run()