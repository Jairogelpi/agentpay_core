import requests
import os
import time
import uuid

# CONFIGURATION
BASE_URL = os.getenv("AGENTPAY_URL", "https://www.agentpay.it.com")

def register_test_agent():
    print(f"🆕 Registering new test agent at {BASE_URL}...")
    try:
        payload = {
            "client_name": f"ResilienceTester_{uuid.uuid4().hex[:6]}",
            "country_code": "ES",
            "agent_role": "Tester"
        }
        resp = requests.post(f"{BASE_URL}/v1/agent/register", json=payload, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            api_key = data.get("api_key")
            agent_id = data.get("agent_id")
            print(f"✅ Registered: {agent_id}")
            return api_key
        else:
            print(f"❌ Registration Failed: {resp.status_code} - {resp.text}")
            return None
    except Exception as e:
        print(f"❌ Registration Error: {e}")
        return None


def test_idempotency_topup(api_key):
    """
    Test "Double Tap" resilience on Topup.
    Calling /v1/topup/auto twice rapidly should result in ONE Stripe charge
    and the SAME transaction ID.
    """
    print("\n🛡️ Testing Idempotency (DoS/Network Retry Protection)...")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {"amount": 50.0}

    print("   👉 Sending First Topup Request...")
    resp1 = requests.post(f"{BASE_URL}/v1/topup/auto", json=payload, headers=headers)
    tx_id_1 = resp1.json().get("tx_id")
    print(f"   ✅ Req 1: {resp1.status_code} | TX ID: {tx_id_1}")

    print("   👉 Sending Second Topup Request (Immediate Retry)...")
    resp2 = requests.post(f"{BASE_URL}/v1/topup/auto", json=payload, headers=headers)
    tx_id_2 = resp2.json().get("tx_id")
    print(f"   ✅ Req 2: {resp2.status_code} | TX ID: {tx_id_2}")

    if tx_id_1 and tx_id_1 == tx_id_2:
        print("   🎉 SUCCESS: IDEMPOTENCY CONFIRMED! (Stripe returned same ID)")
    else:
        print(f"   ❌ FAILURE: Different IDs generated ({tx_id_1} vs {tx_id_2}). Double Charge Risk!")

def test_fast_path_resilience():
    # 1. AUTO-REGISTER
    api_key = register_test_agent()
    
    if not api_key:
        api_key = os.getenv("AGENTPAY_TOKEN")
        if not api_key:
            print("⚠️  Registration failed and AGENTPAY_TOKEN not set. Exiting.")
            return

    # 2. TEST IDEMPOTENCY (NEW)
    test_idempotency_topup(api_key)

    print(f"\n🚀 Testing AgentPay Resilience at {BASE_URL}")
    print("------------------------------------------------")

    payload = {
        "agent_id": "auto_tester", 
        "vendor": "resilience_check.com",
        "amount": 10.00,
        "description": f"Resilience Test {uuid.uuid4().hex[:6]}",
        "justification": "Verifying lazy loading and worker resilience."
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    start_time = time.time()
    try:
        print("📡 Sending Transaction Request...")
        response = requests.post(f"{BASE_URL}/v1/pay", json=payload, headers=headers, timeout=10)
        
        duration = time.time() - start_time
        print(f"⏱️  Response Time: {duration:.2f}s")

        if response.status_code == 200:
            data = response.json()
            status = data.get("status")
            print(f"✅ Response: {response.status_code} | Status: {status}")
            
            # VERIFY FAST PATH
            if duration < 3.0:
                print("⚡ FAST PATH CONFIRMED: API responded quickly (Lazy Loading likely working).")
            else:
                print("⚠️  SLOW RESPONSE: API took > 3s. Check if heavy modules are still loading on API path.")

            # VERIFY ASYNC HANDOFF
            if status == "PROCESSING":
                print("🔄 ASYNC HANDOFF CONFIRMED: Transaction queued for worker.")
                print("   (Check Render logs to verify worker picks it up and recovers if crashed)")
            elif status == "APPROVED":
                print("✅ APPROVED SYNCHRONOUSLY")
            else:
                print(f"ℹ️  Status: {status}")

        else:
            print(f"❌ Error: {response.status_code}")
            print(response.text)

    except Exception as e:
        print(f"🔥 Request Failed: {e}")

if __name__ == "__main__":
    test_fast_path_resilience()
