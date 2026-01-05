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
    
    # 2. TOP UP BALANCE
    log("💰 Topping up balance (Test Mode)...")
    headers = {"Authorization": f"Bearer {api_secret}"}
    try:
        # Top up $500 to cover all tests
        topup_resp = requests.post(f"{BASE_URL}/v1/topup/auto", json={"amount": 500.0}, headers=headers)
        if topup_resp.status_code == 200:
            log("✅ Topup Successful: $500.00")
        else:
            log(f"⚠️ Topup Failed ({topup_resp.status_code}). Proceeding...", "WARNING")
    except Exception as e:
         log(f"⚠️ Topup Error: {e}", "WARNING")

    # 3. TEST SCENARIOS
    scenarios = [
        {
            "name": "TIER 1 (GROQ) - Low Value Safe",
            "vendor": "slack.com",
            "amount": 12.50,
            "description": "Monthly Request for Slack Standard",
            "justification": "Communication tool",
            "expect_tier": "TIER 1"
        },
        {
            "name": "TIER 2 (ORACLE) - High Value Safe",
            "vendor": "aws.amazon.com",
            "amount": 155.00,
            "description": "Monthly AWS EC2 Hosting Bill",
            "justification": "Infrastructure costs",
            "expect_tier": "TIER 2"
        },
        {
            "name": "RISK CHECK - Gambling",
            "vendor": "pokerstars.com",
            "amount": 25.00,
            "description": "Buying chips",
            "justification": "Team building",
            "expect_tier": "REJECTED"
        }
    ]

    for i, test in enumerate(scenarios):
        log(f"\n--- TEST {i+1}: {test['name']} ---")
        pay_payload = {
            "vendor": test['vendor'],
            "amount": test['amount'],
            "description": test['description'],
            "justification": test['justification']
        }
        
        start_time = time.time()
        try:
            pay_resp = requests.post(f"{BASE_URL}/v1/pay", json=pay_payload, headers=headers)
            latency = (time.time() - start_time) * 1000
            
            if pay_resp.status_code != 200:
                log(f"❌ Payment Request Failed: {pay_resp.text}", "ERROR")
                continue

            result = pay_resp.json()
            status = result.get("status")
            tx_id = result.get("transaction_id") or result.get("db_log_id")
            
            log(f"⏱️ Latency: {latency:.2f}ms | Initial Status: {status}")
            
            final_status = status
            # Poll if processing
            if status in ["PROCESSING", "APPROVED_PENDING_AUDIT"] and tx_id:
                log(f"⏳ Polling (TX: {tx_id})...")
                for _ in range(12): # Wait up to 24s
                    time.sleep(2)
                    status_resp = requests.post(f"{BASE_URL}/v1/transactions/status", json={"transaction_id": tx_id}, headers=headers)
                    current_status = status_resp.json().get("status")
                    if current_status in ["APPROVED", "REJECTED"]:
                        final_status = current_status
                        log(f"   => Final: {final_status}")
                        break
                else:
                    log("⚠️ Timed out waiting for worker.", "WARNING")

            log(f"✅ Test Complete. Result: {final_status}")
            
        except Exception as e:
            log(f"❌ Error in test {i+1}: {e}", "ERROR")
        
        time.sleep(1) # Brief pause between tests

    log("\n✨ All tests completed.")

if __name__ == "__main__":
    verify_remote()
