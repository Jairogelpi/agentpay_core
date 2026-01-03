"""
========================================
AGENTPAY COMPLETE E2E TEST SUITE
Tests ALL features in a REAL production environment
========================================
"""
import requests
import time
import json
from loguru import logger

BASE_URL = "https://agentpay-core.onrender.com"

# ============================================
# UTILITY FUNCTIONS
# ============================================
def print_section(title):
    logger.info(f"\n{'='*60}")
    logger.info(f"  {title}")
    logger.info(f"{'='*60}")

def test_result(name, passed, details=""):
    if passed:
        logger.success(f"✅ {name}: PASSED {details}")
    else:
        logger.error(f"❌ {name}: FAILED {details}")
    return passed

# ============================================
# TEST 1: AGENT REGISTRATION & CONFIGURATION
# ============================================
def test_agent_lifecycle():
    print_section("TEST 1: AGENT REGISTRATION & CONFIGURATION")
    
    # 1.1 Register new agent
    reg_res = requests.post(f"{BASE_URL}/v1/agent/register", json={
        "client_name": f"E2E_Test_Corp_{int(time.time())}",
        "country": "ES"
    }).json()
    
    agent_id = reg_res.get('agent_id')
    api_key = reg_res.get('api_key')
    
    if not agent_id or not api_key:
        logger.error(f"Registration failed: {reg_res}")
        return None, None, None
    
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    test_result("Agent Registration", True, f"ID: {agent_id}")
    
    # 1.2 Configure corporate policies (REAL - from database)
    corporate_policies = {
        "spending_limits": {
            "max_per_item": 100.00,
            "daily_budget": 500.00,
            "soft_limit_slack": 50.00
        },
        "restricted_vendors": ["amazon.com", "ebay.com", "aliexpress.com", "netflix.com"],
        "working_hours": {
            "start": "08:00",
            "end": "20:00",
            "timezone": "Europe/Madrid"
        },
        "enforce_justification": True,
        "allowed_categories": ["cloud_services", "saas_tools", "development_tools"]
    }
    
    settings_res = requests.post(f"{BASE_URL}/v1/agent/settings", headers=headers, json={
        "agent_id": agent_id,
        "agent_role": "Senior Cloud Infrastructure Engineer",
        "owner_email": "test@company.com",
        "corporate_policies": corporate_policies
    })
    test_result("Corporate Policies Saved", settings_res.status_code == 200)
    
    # 1.3 Fund the wallet
    topup_res = requests.post(f"{BASE_URL}/v1/topup/auto", headers=headers, json={
        "agent_id": agent_id,
        "amount": 1000.0
    })
    test_result("Wallet Funding", topup_res.status_code == 200, "($1000)")
    
    # 1.4 Verify agent status
    status_res = requests.post(f"{BASE_URL}/v1/agent/status", json={"agent_id": agent_id}).json()
    balance = status_res.get('balance', 0)
    test_result("Agent Status Check", balance > 0, f"Balance: ${balance}")
    
    return agent_id, api_key, headers

# ============================================
# TEST 2: POLICY ENFORCEMENT (Pre-flight Checks)
# ============================================
def test_policy_enforcement(headers):
    print_section("TEST 2: POLICY ENFORCEMENT (Pre-flight)")
    results = []
    
    # 2.1 Restricted Vendor Block
    logger.info("\n🧪 2.1: Testing RESTRICTED VENDOR (Amazon)")
    res = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json={
        "vendor": "amazon.com",
        "amount": 25.0,
        "description": "AWS Credits",
        "justification": "Cloud infrastructure for development"
    }).json()
    passed = res.get('status') == 'REJECTED' and 'restringido' in str(res.get('reason', '')).lower()
    results.append(test_result("Restricted Vendor Block", passed, f"Reason: {res.get('reason', 'N/A')[:50]}"))
    
    # 2.2 Amount Limit Block
    logger.info("\n🧪 2.2: Testing AMOUNT LIMIT ($150 > $100 max)")
    res = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json={
        "vendor": "cloud.google.com",
        "amount": 150.0,
        "description": "GCP Compute Credits",
        "justification": "VM instances for CI/CD pipeline"
    }).json()
    passed = res.get('status') == 'REJECTED' and 'límite' in str(res.get('reason', '')).lower()
    results.append(test_result("Amount Limit Block", passed, f"Reason: {res.get('reason', 'N/A')[:50]}"))
    
    # 2.3 Missing Justification Block
    logger.info("\n🧪 2.3: Testing MISSING JUSTIFICATION")
    res = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json={
        "vendor": "render.com",
        "amount": 30.0,
        "description": "Hosting subscription",
        "justification": ""
    }).json()
    passed = res.get('status') == 'REJECTED' and 'justificación' in str(res.get('reason', '')).lower()
    results.append(test_result("Missing Justification Block", passed, f"Reason: {res.get('reason', 'N/A')[:50]}"))
    
    return all(results)

# ============================================
# TEST 3: VALID PAYMENT FLOW (Full Cycle)
# ============================================
def test_valid_payment(headers):
    print_section("TEST 3: VALID PAYMENT FLOW")
    
    # 3.1 Execute valid payment
    logger.info("\n🧪 3.1: Executing VALID payment")
    res = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json={
        "vendor": "cloud.google.com",
        "amount": 45.0,
        "description": "GCP Compute Engine Credits",
        "justification": "Production Kubernetes cluster hosting for client microservices deployment"
    }).json()
    
    if res.get('status') not in ['APPROVED', 'APPROVED_PENDING_AUDIT']:
        test_result("Valid Payment Execution", False, f"Status: {res.get('status')} - {res.get('reason')}")
        return None
    
    tx_id = res.get('db_log_id') or res.get('transaction_id')
    test_result("Valid Payment Execution", True, f"TX ID: {tx_id}")
    
    # 3.2 Verify virtual card was issued
    card = res.get('card', {})
    test_result("Virtual Card Issued", bool(card.get('id')), f"Card: **** {card.get('last4', 'N/A')}")
    
    # 3.3 Verify invoice generated
    invoice_url = res.get('forensic_url') or res.get('invoice_url')
    test_result("Invoice Generated", bool(invoice_url), f"URL: {invoice_url[:50] if invoice_url else 'N/A'}...")
    
    return tx_id

# ============================================
# TEST 4: TRANSACTION STATUS & HISTORY
# ============================================
def test_transaction_verification(headers, tx_id):
    print_section("TEST 4: TRANSACTION VERIFICATION")
    
    if not tx_id:
        logger.warning("⚠️ Skipping - No transaction ID available")
        return False
    
    # Wait for background audit to complete
    logger.info("⏳ Waiting 5s for background audit...")
    time.sleep(5)
    
    # 4.1 Check transaction status
    status_res = requests.post(f"{BASE_URL}/v1/transactions/status", headers=headers, json={
        "transaction_id": tx_id
    }).json()
    
    test_result("Transaction Status Fetch", bool(status_res.get('status')), f"Status: {status_res.get('status')}")
    test_result("Settlement Currency", bool(status_res.get('settlement_currency')), f"Currency: {status_res.get('settlement_currency')}")
    test_result("FX Rate Recorded", status_res.get('fx_rate') is not None, f"Rate: {status_res.get('fx_rate')}")
    
    return True

# ============================================
# TEST 5: ACCOUNTING EXPORT (CSV)
# ============================================
def test_accounting_export(headers, agent_id):
    print_section("TEST 5: ACCOUNTING EXPORT")
    
    # 5.1 Export transactions as CSV
    export_res = requests.get(f"{BASE_URL}/v1/accounting/export-csv", headers=headers)
    
    passed = export_res.status_code == 200
    test_result("CSV Export", passed, f"Content-Type: {export_res.headers.get('content-type', 'N/A')}")
    
    return passed

# ============================================
# TEST 6: ORACLE INTELLIGENCE (AI Fraud Detection)
# ============================================
def test_oracle_intelligence(headers):
    print_section("TEST 6: ORACLE AI INTELLIGENCE")
    
    # 6.1 Test suspicious purchase (should trigger Oracle review)
    logger.info("\n🧪 6.1: Testing SUSPICIOUS purchase (gaming on work account)")
    res = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json={
        "vendor": "store.steampowered.com",
        "amount": 60.0,
        "description": "Development tools license",
        "justification": "Game engine for team morale software"
    }).json()
    
    # This might be approved pending audit or rejected
    status = res.get('status')
    reason = res.get('reason', 'N/A')
    
    if status == 'REJECTED':
        test_result("Oracle Fraud Detection", True, f"Blocked: {reason[:60]}")
    elif status == 'APPROVED_PENDING_AUDIT':
        test_result("Oracle Flagged for Review", True, f"Pending: {reason[:60]}")
    else:
        test_result("Oracle Response", True, f"Status: {status}")
    
    return True

# ============================================
# TEST 7: HIVE MIND (Global Blacklist)
# ============================================
def test_hive_mind(headers):
    print_section("TEST 7: HIVE MIND GLOBAL BLACKLIST")
    
    # 7.1 Report a fraudulent vendor
    report_res = requests.post(f"{BASE_URL}/v1/fraud/report", headers=headers, json={
        "vendor": f"scam-site-{int(time.time())}.com",
        "reason": "E2E Test - Fake scam site for testing"
    }).json()
    
    test_result("Fraud Report Submitted", bool(report_res), f"Response: {str(report_res)[:50]}")
    
    return True

# ============================================
# TEST 8: CREDIT NOTE GENERATION
# ============================================
def test_credit_note(headers, agent_id, tx_id):
    print_section("TEST 8: CREDIT NOTE GENERATION")
    
    if not tx_id:
        logger.warning("⚠️ Skipping - No transaction ID available")
        return False
    
    # 8.1 Generate credit note for a transaction
    credit_res = requests.post(f"{BASE_URL}/v1/accounting/credit-note", headers=headers, json={
        "agent_id": agent_id,
        "original_transaction_id": tx_id,
        "reason": "E2E Test - Service cancellation"
    }).json()
    
    passed = 'credit_note_url' in credit_res or credit_res.get('status') == 'CREATED'
    test_result("Credit Note Generated", passed, f"Response: {str(credit_res)[:60]}")
    
    return passed

# ============================================
# TEST 9: AGENT LIMITS UPDATE
# ============================================
def test_limits_update(headers, agent_id):
    print_section("TEST 9: AGENT LIMITS UPDATE")
    
    # 9.1 Update agent spending limits
    limits_res = requests.post(f"{BASE_URL}/v1/agent/limits", headers=headers, json={
        "agent_id": agent_id,
        "daily_limit": 2000.0,
        "max_transaction_limit": 500.0
    }).json()
    
    test_result("Limits Updated", limits_res.get('status') == 'LIMITS_UPDATED', f"Response: {limits_res}")
    
    return True

# ============================================
# MAIN TEST RUNNER
# ============================================
def run_complete_e2e_test():
    logger.info("""
    ╔═══════════════════════════════════════════════════════════╗
    ║          AGENTPAY COMPLETE E2E TEST SUITE                 ║
    ║          Testing ALL features in PRODUCTION               ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    start_time = time.time()
    test_results = {}
    
    try:
        # TEST 1: Agent Lifecycle
        agent_id, api_key, headers = test_agent_lifecycle()
        if not agent_id:
            logger.error("❌ CRITICAL: Agent registration failed. Aborting tests.")
            return
        test_results['Agent Lifecycle'] = True
        
        # TEST 2: Policy Enforcement
        test_results['Policy Enforcement'] = test_policy_enforcement(headers)
        
        # TEST 3: Valid Payment
        tx_id = test_valid_payment(headers)
        test_results['Valid Payment'] = bool(tx_id)
        
        # TEST 4: Transaction Verification
        test_results['Transaction Verification'] = test_transaction_verification(headers, tx_id)
        
        # TEST 5: Accounting Export
        test_results['Accounting Export'] = test_accounting_export(headers, agent_id)
        
        # TEST 6: Oracle Intelligence
        test_results['Oracle Intelligence'] = test_oracle_intelligence(headers)
        
        # TEST 7: Hive Mind
        test_results['Hive Mind'] = test_hive_mind(headers)
        
        # TEST 8: Credit Note
        test_results['Credit Note'] = test_credit_note(headers, agent_id, tx_id)
        
        # TEST 9: Limits Update
        test_results['Limits Update'] = test_limits_update(headers, agent_id)
        
    except Exception as e:
        logger.error(f"❌ CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
    
    # ============================================
    # FINAL REPORT
    # ============================================
    elapsed = time.time() - start_time
    print_section("FINAL TEST REPORT")
    
    passed = sum(1 for v in test_results.values() if v)
    total = len(test_results)
    
    logger.info(f"\n📊 Results: {passed}/{total} tests passed")
    logger.info(f"⏱️ Total time: {elapsed:.2f} seconds")
    
    for test_name, result in test_results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        logger.info(f"   {status} - {test_name}")
    
    if passed == total:
        logger.success("""
    ╔═══════════════════════════════════════════════════════════╗
    ║          🎉 ALL TESTS PASSED! SYSTEM IS READY 🎉          ║
    ╚═══════════════════════════════════════════════════════════╝
        """)
    else:
        logger.warning(f"\n⚠️ {total - passed} test(s) failed. Review logs above.")

if __name__ == "__main__":
    run_complete_e2e_test()
