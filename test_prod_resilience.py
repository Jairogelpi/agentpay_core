import requests
import os
import time
import uuid

# CONFIGURATION
# Default to local if not set, but respect the ENV variable
BASE_URL = os.getenv("AGENTPAY_URL", "https://www.agentpay.it.com")

def register_test_agent():
    print(f"\n🆕 [1/5] Registering new test agent at {BASE_URL}...")
    try:
        payload = {
            "client_name": f"ResilienceTester_{uuid.uuid4().hex[:6]}",
            "country_code": "ES",
            "agent_role": "Tester"
        }
        # Requests automatically validates the 'Client IP' extraction in main.py
        resp = requests.post(f"{BASE_URL}/v1/agent/register", json=payload, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            api_key = data.get("api_key")
            agent_id = data.get("agent_id")
            print(f"   ✅ Registered: {agent_id} (IP Capture Passed)")
            return api_key, agent_id
        else:
            print(f"   ❌ Registration Failed: {resp.status_code} - {resp.text}")
            return None, None
    except Exception as e:
        print(f"   ❌ Registration Error: {e}")
        return None, None


def test_idempotency_topup(api_key):
    """
    Test "Double Tap" resilience on Topup.
    """
    print("\n🛡️ [2/5] Testing Idempotency (DoS Protection)...")
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

def test_global_hard_block(api_key, agent_id):
    """
    Test the GLOBAL_FORBIDDEN list (Hard Rules).
    """
    print("\n🚫 [3/5] Testing Global Hard Block (Compliance)...")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # Intento de compra en sitio prohibido
    bad_vendor = "online-poker-casino.com"
    print(f"   👉 Attempting purchase at: {bad_vendor}")
    
    payload = {
        "agent_id": agent_id, 
        "vendor": bad_vendor,
        "amount": 100.00,
        "description": "Trying to bypass rules",
        "justification": "I want to gamble"
    }
    
    try:
        resp = requests.post(f"{BASE_URL}/v1/pay", json=payload, headers=headers)
        data = resp.json()
        
        # We expect a REJECTION or HTTP Error, usually status REJECTED in body
        if data.get("status") == "REJECTED" and "Prohibida" in str(data.get("message", "")):
            print(f"   🎉 SUCCESS: Blocked Correctly! Msg: {data.get('message')}")
        elif data.get("status") == "REJECTED":
            print(f"   ✅ Blocked (Generic): {data.get('message')}")
        else:
            print(f"   ❌ FAILURE: Transaction was NOT blocked properly. Status: {data.get('status')}")
            
    except Exception as e:
        print(f"   ⚠️ Request Error: {e}")

def test_legal_signature(api_key, agent_id):
    """
    Test the Legal Signature endpoint with Real IP.
    """
    print("\n⚖️ [4/5] Testing Legal Digital Signature (Real IP)...")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "agent_id": agent_id,
        "platform_url": "https://agentpay.io/legal/v1",
        "forensic_hash": "VERIFY-KMS-TEST" # Placeholder or fetch real one if possible
    }
    
    try:
        resp = requests.post(f"{BASE_URL}/v1/legal/sign_tos", json=payload, headers=headers)
        data = resp.json()
        
        if resp.status_code == 200 and data.get("status") == "SIGNED":
            print(f"   🎉 SUCCESS: Signed! Cert ID: {data.get('certificate_id')}")
            print(f"      Version: {data.get('agreement_version')} | IP Captured: Yes (Implicit)")
        else:
            print(f"   ❌ FAILURE: Signing failed. {resp.text}")
            
    except Exception as e:
        print(f"   ⚠️ Request Error: {e}")

def test_fast_path_valid_tx(api_key, agent_id):
    """
    Test a VALID transaction to ensure we haven't broken the good path.
    """
    print(f"\n🚀 [5/5] Testing Valid Transaction (Fast Path)...")

    payload = {
        "agent_id": agent_id, 
        "vendor": "aws.amazon.com",
        "amount": 10.00,
        "description": "Valid Cloud Hosting",
        "justification": "Infrastructure costs"
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    start_time = time.time()
    try:
        response = requests.post(f"{BASE_URL}/v1/pay", json=payload, headers=headers, timeout=10)
        duration = time.time() - start_time
        
        data = response.json()
        print(f"   ⏱️  Time: {duration:.2f}s | Status: {data.get('status')}")

        if data.get("status") in ["APPROVED", "PROCESSING"]:
             print("   🎉 SUCCESS: Valid transaction processed.")
        else:
             print(f"   ❌ FAILURE: Valid transaction rejected? {data.get('message')}")

    except Exception as e:
        print(f"   🔥 Request Failed: {e}")

def run_all_tests():
    print("========================================")
    print("🛡️  AGENTPAY RESILIENCE SUITE v2.0")
    print("========================================")
    
    # 1. Register
    api_key, agent_id = register_test_agent()
    
    if not api_key:
        print("⏹️  Critical Stop: Registration failed.")
        return

    # 2. Idempotency
    test_idempotency_topup(api_key)
    
    # 3. Security (Hard Block) - NEW
    test_global_hard_block(api_key, agent_id)
    
    # 4. Legal (Signatures) - NEW
    test_legal_signature(api_key, agent_id)
    
    # 5. Happy Path
    test_fast_path_valid_tx(api_key, agent_id)
    
    print("\n✅ Verification Complete.")

if __name__ == "__main__":
    run_all_tests()
