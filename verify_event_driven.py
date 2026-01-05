import requests
import time
import json
import sys

# Configuration
BASE_URL = "https://www.agentpay.it.com"
# BASE_URL = "http://localhost:8000" # Uncomment for local testing

def log(msg, type="INFO"):
    print(f"[{type}] {msg}")

def verify_remote():
    log(f"🚀 Starting Remote Verification on {BASE_URL}...")
    
    # 1. REGISTER AGENT
    log("📝 Registering new Test Agent...")
    reg_payload = {
        "client_name": "EventDrivenTester",
        "country": "ES",
        "agent_role": "QA Automation"
    }
    
    try:
        reg_resp = requests.post(f"{BASE_URL}/v1/agent/register", json=reg_payload)
        reg_resp.raise_for_status()
        agent_data = reg_resp.json()
        
        agent_id = agent_data.get("agent_id")
        api_secret = agent_data.get("api_key")
        
        if not agent_id or not api_secret:
            log("❌ Registration Failed: Missing credentials", "ERROR")
            return
            
        log(f"✅ Agent Registered: {agent_id}")
        # log(f"🔑 Secret: {api_secret[:10]}...")
        
    except Exception as e:
        log(f"❌ Registration Request Failed: {e}", "ERROR")
        if hasattr(e, 'response') and e.response: lo(f"Response: {e.response.text}", "ERROR")
        return

    # 2. TOP UP BALANCE (Optional but good practice if balance is 0)
    # Uses the auto-topup endpoint for testing if available, or assumes standard registration gives some credit?
    # Usually registration gives 0.0. Let's try to verify via status, but we might need to top up.
    # Looking at main.py: /v1/topup/auto exists but requires verify_api_key? No, assumes local call or test mode.
    # Actually, let's try to proceed. If rejection due to funds, we'll know.
    # But usually test agents might need funds.
    # Let's try the payment anyway. A "Saldo insuficiente" rejection is also a valid result from the Engine/Worker flow.
    # But we want to test the ASYNC flow.
    # The fast path checks balance first *synchronously* in `evaluate_fast_path`.
    # So if balance is 0, it will return REJECTED immediately and NOT queue to Redis.
    # We MUST top up.
    
    log("💰 Topping up balance (Test Mode)...")
    headers = {"Authorization": f"Bearer {api_secret}"}
    try:
        # Try the auto topup if it works, or maybe /v1/topup/direct_charge?
        # /v1/topup/auto takes agent_id and amount, and requires auth.
        topup_resp = requests.post(f"{BASE_URL}/v1/topup/auto", json={"amount": 100.0}, headers=headers)
        if topup_resp.status_code == 200:
            log("✅ Topup Successful: $100.00")
        else:
            log(f"⚠️ Topup Failed ({topup_resp.status_code}). Proceeding anyway (might fail due to funds).", "WARNING")
    except Exception as e:
         log(f"⚠️ Topup Error: {e}", "WARNING")

    # 3. REQUEST PAYMENT
    log("💸 Requesting Payment (Async Check)...")
    pay_payload = {
        "vendor": "openai.com",
        "amount": 5.00,
        "description": "Async Architecture Verification",
        "justification": "Testing Redis Streams Worker"
    }
    
    start_time = time.time()
    try:
        pay_resp = requests.post(f"{BASE_URL}/v1/pay", json=pay_payload, headers=headers)
        latency = (time.time() - start_time) * 1000
        
        log(f"⏱️ API Latency: {latency:.2f}ms")
        
        if pay_resp.status_code != 200:
             log(f"❌ Payment Request Failed: {pay_resp.text}", "ERROR")
             return

        result = pay_resp.json()
        status = result.get("status")
        
        log(f"📋 Initial Status: {status}")
        
        if status == "PROCESSING":
            log("✅ SUCCESS: Received PROCESSING status immediately (Fast Path Active).")
        elif status == "APPROVED_PENDING_AUDIT":
            log("✅ SUCCESS: Approved Pending Audit (This might be the synchronous fallback or fast pass return).")
        elif status == "REJECTED":
            log(f"⚠️ Transaction Rejected: {result.get('message')}")
            return
        else:
            log(f"⚠️ Unexpected Status: {status}")

        # 4. POLL FOR COMPLETION (If Processing)
        tx_id = result.get("transaction_id") or result.get("db_log_id")
        
        if status == "PROCESSING" and tx_id:
            log(f"⏳ Polling for final status (TX: {tx_id})...")
            for i in range(10):
                time.sleep(2)
                try:
                    status_resp = requests.post(f"{BASE_URL}/v1/transactions/status", json={"transaction_id": tx_id}, headers=headers)
                    current_status = status_resp.json().get("status")
                    log(f"   Attempt {i+1}: {current_status}")
                    
                    if current_status in ["APPROVED", "REJECTED"]:
                        log(f"✅ Final Status Reached: {current_status}")
                        break
                except Exception as e:
                    pass
            else:
                log("⚠️ Polling timed out. Worker might be slow or ID mismatch.", "WARNING")

    except Exception as e:
        log(f"❌ Error during payment request: {e}", "ERROR")

if __name__ == "__main__":
    verify_remote()
