import requests
import time

def test_invisible_mode():
    url = "https://agentpay-core.onrender.com/v1/pay"
    
    # We use our special test domain that triggers MEDIUM_RISK
    payload = {
        "agent_id": "real_agent_test",
        "vendor": "https://test-medium-risk.com/checkout",
        "amount": 15.00,
        "description": "Subscription Renewal (Invisible Mode Test)"
    }
    
    print(f"🚀 Sending Request to {url}...")
    print(f"📦 Payload: {payload}")
    
    try:
        response = requests.post(url, json=payload)
        print(f"Status Code: {response.status_code}")
        
        data = response.json()
        print(f"Response: {data}")
        
        if response.status_code == 200:
            msg = data.get("message", "")
            if "Identity Incinerated" in msg:
                print("✅ SUCCESS: Invisible Mode triggered and Burner Identity destroyed!")
            else:
                print("⚠️  Warning: Transaction approved but 'Identity Incinerated' signature missing.")
                print("Check valid MEDIUM_RISK trigger.")
        else:
            print("❌ Request Failed.")
            
    except Exception as e:
        print(f"❌ Connection Error: {e}")
        print("Make sure the uvicorn server is running on localhost:8000")

if __name__ == "__main__":
    test_invisible_mode()
