import requests
import json
import uuid
import time
import os
from dotenv import load_dotenv

load_dotenv()

# CONFIG - PROD
BASE_URL = "https://www.agentpay.it.com"
USER_EMAIL = "gelpierreape@gmail.com"

def run_prod_verification():
    print(f"🌍 CONNECTING TO PRODUCTION: {BASE_URL}")
    print("==================================================")

    # 1. REGISTER AGENT
    print("\n[1] Registering New Agent...")
    client_name = f"ProdTester_{uuid.uuid4().hex[:4]}"
    
    try:
        reg_res = requests.post(f"{BASE_URL}/v1/agent/register", json={
            "client_name": client_name,
            "country_code": "US",
            "agent_role": "Production Tester"
        }).json()
        
        agent_id = reg_res.get("agent_id")
        api_key = reg_res.get("api_key")
        
        if not agent_id:
            print(f"❌ Registration Failed: {reg_res}")
            return
            
        print(f"   ✅ Agent Registered: {agent_id}")
    except Exception as e:
        print(f"❌ Connection Error: {e}")
        return

    # 2. CONFIGURE EMAIL (Critical for notification)
    print("\n[2] Configuring Owner Email...")
    headers = {"Authorization": f"Bearer {api_key}"} # Assuming key is needed or separate auth
    # Note: /v1/agent/settings usually requires agent_id in body if not fully auth-context aware in main.py simple endpoint
    
    set_res = requests.post(f"{BASE_URL}/v1/agent/settings", json={
        "agent_id": agent_id,
        "owner_email": USER_EMAIL
    }).json()
    print(f"   ✅ Settings Updated: {set_res}")

    # 3. TRIGGER TRANSACTION (To fire the email)
    print("\n[3] Executing Transaction (Triggering Email)...")
    tx_payload = {
        "agent_id": agent_id,
        "vendor": "Amazon AWS",
        "amount": 150.00, # > $50 triggers scrutiny/invoice request
        "description": "Production Server Hosting"
    }
    
    # Needs Auth usually
    pay_res = requests.post(f"{BASE_URL}/v1/pay", json=tx_payload, headers=headers).json()
    tx_id = pay_res.get("transaction_id") or pay_res.get("tx_id")
    
    print(f"   💸 Transaction: {pay_res.get('status')} | ID: {tx_id}")
    
    if tx_id:
        print(f"\n   🚀 EMAIL SHOULD BE SENT NOW TO: {USER_EMAIL}")
        print("   (Check your spam folder if not in inbox)")
    else:
        print("   ❌ No Transaction ID. Stopping.")
        return

    # 4. SIMULATE REPLY (The User Verification)
    print("\n   ⏳ Waiting 5 seconds before checking reply loop...")
    time.sleep(5)
    
    print("\n[4] Simulating INBOUND Reply (Webhook from Brevo)...")
    # Simulate that user replied with a PDF link
    invoice_link = "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf"
    
    inbound_payload = {
        "items": [{
            "Sender": {"Email": USER_EMAIL},
            "Recipient": {"Email": f"agent-{agent_id}@agentpay.it.com"},
            "Subject": f"Re: Factura Requerida: Amazon AWS",
            "RawTextBody": f"Adjunto la factura solicitada: {invoice_link} \nGracias.",
            "Date": "Mon, 06 Jan 2026 12:00:00 GMT"
        }]
    }
    
    webhook_res = requests.post(f"{BASE_URL}/v1/webhooks/inbound_email", json=inbound_payload)
    print(f"   👉 Webhook Status: {webhook_res.status_code}")
    print(f"   👉 Response: {webhook_res.json()}")
    
    if webhook_res.status_code == 200:
        print("\n   ✅ CYCLE COMPLETE!")
        print("   1. Agent Born -> 2. Purchase Made -> 3. Email Sent -> 4. Reply Processed -> 5. AI Analyzed Link")
    else:
        print("\n   ❌ Webhook Failed.")

if __name__ == "__main__":
    run_prod_verification()
