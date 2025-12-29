import requests
import json
import sys

BASE_URL = "https://agentpay-core.onrender.com"

def test_invisible_mode():
    print("--- 1. Registering New Agent (with Welcome Bonus) ---")
    reg_url = f"{BASE_URL}/v1/agent/register"
    try:
        reg_res = requests.post(reg_url, json={"client_name": "TestCorp Inc."})
        
        if reg_res.status_code != 200:
            print(f"❌ Registration Failed: {reg_res.text}")
            return

        agent_data = reg_res.json()
        agent_id = agent_data.get("agent_id")
        print(f"✅ Agent Created: {agent_id}")
        
        print("--- 2. Testing Invisible Mode Payment ---")
        pay_url = f"{BASE_URL}/v1/pay"
        payload = {
            "agent_id": agent_id,
            "vendor": "https://test-medium-risk.com/checkout",
            "amount": 15.00,
            "description": "Invisible Mode Test"
        }
        
        response = requests.post(pay_url, json=payload)
        print(f"Status Code: {response.status_code}")
        
        try:
             data = response.json()
             print(f"Response: {data}")
             
             if response.status_code == 200:
                msg = data.get("message", "")
                if "Identity Incinerated" in msg:
                    print("✅ SUCCESS: Invisible Mode active & Burner Identity destroyed!")
                else:
                    print("⚠️  Warning: Transaction approved but 'Identity Incinerated' missing.")
             else:
                print("❌ Request Failed.")
        except Exception as e:
             print(f"❌ JSON Error: {e}")
             print(f"Raw: {response.text}")
            
    except Exception as e:
        print(f"❌ Connection Error: {e}")

if __name__ == "__main__":
    test_invisible_mode()
