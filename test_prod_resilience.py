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
            "country_code": "US",
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

def test_fast_path_resilience():
    # 1. AUTO-REGISTER
    api_key = register_test_agent()
    
    if not api_key:
        # Fallback to env var
        api_key = os.getenv("AGENTPAY_TOKEN")
        if not api_key:
            print("⚠️  Registration failed and AGENTPAY_TOKEN not set. Exiting.")
            return

    print(f"🚀 Testing AgentPay Resilience at {BASE_URL}")
    print("------------------------------------------------")

    payload = {
        "agent_id": "auto_tester", # The endpoint will override this with the token's agent_id
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
                print("✅ APPROVED SYNCHRONOUSLY (Note: Might trigger heavy load if not async)")
            else:
                print(f"ℹ️  Status: {status}")

        else:
            print(f"❌ Error: {response.status_code}")
            print(response.text)

    except Exception as e:
        print(f"🔥 Request Failed: {e}")

if __name__ == "__main__":
    test_fast_path_resilience()
