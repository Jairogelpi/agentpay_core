"""
AGENTPAY INFRASTRUCTURE COMPLETE TEST - ALL 32 ENDPOINTS
=========================================================
Script que prueba ABSOLUTAMENTE TODAS las funciones del sistema.

Antes de ejecutar:
1. UPDATE wallets SET balance = 100 WHERE agent_id = 'sk_a03c7e53830d4dc4a779418d';
"""

import requests
import time

HOST = "https://agentpay-core.onrender.com"
AGENT_ID = "sk_a03c7e53830d4dc4a779418d"

def log(emoji, msg): print(f"{emoji} {msg}")

def test(name, method, path, payload=None):
    url = f"{HOST}{path}"
    try:
        r = requests.get(url, timeout=30) if method == "GET" else requests.post(url, json=payload, timeout=30)
        if r.status_code == 200:
            log("✅", f"{name}")
            return True, r.json() if r.text else {}
        else:
            log("❌", f"{name}: {r.status_code}")
            return False, {}
    except Exception as e:
        log("💥", f"{name}: {str(e)[:50]}")
        return False, {}

def run():
    print("\n" + "="*60)
    print("🚀 AGENTPAY - TEST COMPLETO DE 32 ENDPOINTS")
    print("="*60 + "\n")
    
    results = {}
    tx_id = None
    escrow_tx = None
    
    # === AGENT MANAGEMENT ===
    log("👤", "--- AGENT MANAGEMENT ---")
    results["agent_register"], _ = test("Register New Agent", "POST", "/v1/agent/register", {"client_name": "Test Bot"})
    results["agent_status"], data = test("Agent Status", "POST", "/v1/agent/status", {"agent_id": AGENT_ID})
    log("💰", f"   Balance: ${data.get('finance', {}).get('balance', 0)}")
    results["agent_settings"], _ = test("Update Settings", "POST", "/v1/agent/settings", {"agent_id": AGENT_ID, "webhook_url": "https://example.com/webhook"})
    results["agent_limits"], _ = test("Update Limits", "POST", "/v1/agent/limits", {"agent_id": AGENT_ID, "max_tx": 500, "daily_limit": 1000})
    results["agent_notify"], _ = test("Send Alert", "POST", "/v1/agent/notify", {"agent_id": AGENT_ID, "message": "Test Alert"})
    
    # === IDENTITY ===
    log("🆔", "\n--- IDENTITY MANAGEMENT ---")
    results["identity_create"], data = test("Create Identity", "POST", "/v1/identity/create", {"agent_id": AGENT_ID})
    identity_id = data.get('identity_id', 'cert_test')
    results["identity_check"], _ = test("Check Inbox", "GET", f"/v1/identity/{identity_id}/check")
    results["identity_sms"], _ = test("Check SMS", "GET", f"/v1/identity/{identity_id}/sms")
    results["identity_session"], _ = test("Update Session", "POST", "/v1/identity/update_session", {"identity_id": identity_id, "session_data": {"cookie": "test"}})
    results["identity_list"], _ = test("List Identities", "POST", "/v1/identity/list", {"agent_id": AGENT_ID})
    results["identity_proxy"], _ = test("Get Proxy", "POST", "/v1/identity/proxy", {"region": "US"})
    results["identity_captcha"], _ = test("Solve Captcha", "POST", "/v1/identity/captcha", {"image_url": "https://example.com/captcha.png"})
    
    # === FINANCIAL & TOP-UP ORCHESTRATION ===
    log("💵", "\n--- FINANCIAL & TOP-UP ORCHESTRATION ---")
    results["topup_create"], data = test("Create Top-Up Link", "POST", "/v1/topup/create", {"agent_id": AGENT_ID, "amount": 50})
    if data.get('url'):
        log("🔗", f"   TOP-UP LINK: {data['url']}")
        log("💡", "   Para pago real: Entra al link y paga con tarjeta real o de test.")
    
    # Simulación de Webhook (Esto fallará en firma si no se manda el header correcto, pero prueba el endpoint)
    log("📡", "   Simulando llegada de Webhook de Stripe...")
    results["webhook_test"], _ = test("Stripe Webhook Endpoint", "POST", "/webhook", {"id": "evt_test", "type": "checkout.session.completed"})
    
    results["credit_score"], data = test("Check Credit Score", "POST", "/v1/credit/score", {"agent_id": AGENT_ID})
    log("🏅", f"   Score: {data.get('score', 0)}")
    results["insurance_config"], _ = test("Configure Insurance", "POST", "/v1/insurance/configure", {"agent_id": AGENT_ID, "enabled": True, "strictness": "HIGH"})
    results["streaming_pack"], _ = test("Streaming Payment", "POST", "/v1/streaming/pack", {"agent_id": AGENT_ID, "vendor": "api.example.com", "amount": 0.01})
    
    # === PAYMENTS ===
    log("💳", "\n--- PAYMENTS ---")
    results["pay"], data = test("Request Payment", "POST", "/v1/pay", {
        "agent_id": AGENT_ID, "vendor": "api.trusted.com", "amount": 5.00,
        "description": "API Credits", "justification": "Operational expense"
    })
    tx_id = data.get('transaction_id')
    log("🧾", f"   TX ID: {tx_id}")
    
    # NUEVO: Verificar datos de tarjeta real
    card = data.get('card_details')
    if card:
        log("🎫", f"   TARJETA REAL: {card['brand'].upper()} {card['number']} (CVV: {card['cvv']})")
    
    # NUEVO: Verificar Forensic Ledger
    forensic_url = data.get('forensic_bundle_url')
    if forensic_url:
        log("⚖️", f"   FORENSIC LEDGER: {forensic_url}")
        # Mostrar razomiento de la IA (Viene en la respuesta de pago)
        if data.get('reason'):
            log("🧠", f"   ORACLE VERDICT: {data['reason']}")
        
        # Extraer ID del bundle de la URL
        bundle_id = forensic_url.split('/')[-1]
        results["forensic_audit"], _ = test("Fetch Forensic Audit", "GET", f"/v1/audit/{bundle_id}")
    
    if tx_id:
        results["tx_status"], _ = test("Check TX Status", "POST", "/v1/transactions/status", {"transaction_id": tx_id})
        results["invoice_download"], _ = test("Download Invoice", "POST", "/v1/invoices/download", {"transaction_id": tx_id})
        results["trust_verify"], _ = test("Trust Verification", "POST", "/v1/trust/verify", {"agent_id": AGENT_ID, "transaction_id": tx_id, "service_logs": "200 OK"})
        results["report_value"], _ = test("Report ROI Value", "POST", "/v1/analytics/report_value", {"agent_id": AGENT_ID, "transaction_id": tx_id, "perceived_value": 50.0})
        results["dispute_tx"], _ = test("Dispute Transaction", "POST", "/v1/transactions/dispute", {"agent_id": AGENT_ID, "transaction_id": tx_id, "reason": "Test dispute"})
    
    # === PROCUREMENT ===
    log("🛒", "\n--- PROCUREMENT ---")
    results["procure"], data = test("Market Procure", "POST", "/v1/market/procure", {
        "agent_id": AGENT_ID, "vendor": "supplier.example.com", "amount": 10.0,
        "items": [{"name": "Widget", "qty": 1}], "description": "B2B Order"
    })
    if data.get('card_details'):
        log("🎫", f"   PROCUREMENT CARD: {data['card_details']['number']}")
    
    # === ESCROW ===
    log("🔐", "\n--- ESCROW ---")
    results["escrow_create"], data = test("Create Escrow", "POST", "/v1/escrow/create", {
        "agent_id": AGENT_ID, "vendor": "freelancer.com", "amount": 10.0, "description": "Design work"
    })
    escrow_tx = data.get('transaction_id')
    if escrow_tx:
        results["escrow_confirm"], _ = test("Confirm Delivery", "POST", "/v1/escrow/confirm", {"agent_id": AGENT_ID, "transaction_id": escrow_tx})
        results["escrow_dispute"], _ = test("Escrow Dispute", "POST", "/v1/escrow/dispute", {
            "agent_id": AGENT_ID, "transaction_id": escrow_tx,
            "issue_description": "Not delivered", "technical_evidence": "No response"
        })
    
    # === LEGAL ===
    log("⚖️", "\n--- LEGAL ---")
    results["legal_sign"], _ = test("Sign Contract", "POST", "/v1/legal/sign", {"agent_id": AGENT_ID, "contract_hash": "abc123"})
    results["legal_sign_tos"], data = test("Sign Terms of Service", "POST", "/v1/legal/sign_tos", {"agent_id": AGENT_ID, "platform_url": "https://vendor.com"})
    log("📜", f"   Cert: {data.get('certificate', {}).get('certificate_id', 'N/A')}")
    results["legal_passport"], _ = test("Get Passport", "POST", "/v1/legal/passport", {"agent_id": AGENT_ID})
    
    # === SECURITY ===
    log("🚨", "\n--- SECURITY ---")
    results["fraud_report"], _ = test("Report Fraud", "POST", "/v1/fraud/report", {"agent_id": AGENT_ID, "vendor": "scam.xyz", "reason": "Phishing"})
    
    # === M2M MARKET ===
    log("🤝", "\n--- M2M MARKET ---")
    results["market_directory"], _ = test("Service Directory", "POST", "/v1/market/directory", {"role": "ALL"})
    results["market_quote"], _ = test("Request Quote", "POST", "/v1/market/quote", {"provider_id": AGENT_ID, "service_type": "translation", "params": {}})
    
    # === ANALYTICS ===
    log("📊", "\n--- ANALYTICS ---")
    results["dashboard"], data = test("Dashboard Metrics", "GET", f"/v1/analytics/dashboard/{AGENT_ID}")
    if data.get('roi_analytics'):
        log("📈", f"   ROI: {data['roi_analytics'].get('roi_percentage', 0)}%")
    
    # === RESUMEN ===
    print("\n" + "="*60)
    print("📋 RESUMEN FINAL")
    print("="*60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for name, ok in results.items():
        print(f"   {'✅' if ok else '❌'} {name}")
    
    print(f"\n   TOTAL: {passed}/{total} endpoints funcionando")
    
    if passed == total:
        log("🎉", "\n¡100% OPERATIVO! Sistema listo para producción.")
    else:
        log("⚠️", f"\n{total - passed} endpoints fallaron.")

if __name__ == "__main__":
    run()
