import requests
import json
import base64
import time
import os
import uuid

# Base URL as configured
BASE_URL = os.getenv("AGENTPAY_URL", "https://www.agentpay.it.com")
# Or localhost for direct testing if preferred, but user asked for "www.agentpay.it.com" semantics
# If strictly local testing is needed: BASE_URL = "http://localhost:8000"

def create_dummy_invoice_pdf():
    """Create a minimal PDF file in memory (Base64 encoded)."""
    # This is a very simple valid PDF header/footer.
    # It won't have text readable by AI unless we use a real PDF library, 
    # but for testing the upload pipeline it's sufficient.
    # To test AI Vision, we really need an image. Let's use a dummy image instead.
    
    # 1x1 Pixel WHITE JPEG
    dummy_img = (
        "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwH7+AD/2Q=="
    )
    return dummy_img

def run_reconciliation_test():
    print("===========================================")
    print("🧾 VERIFYING INVOICE RECONCILIATION FLOW")
    print("===========================================")
    print(f"Target: {BASE_URL}")

    # 1. REGISTER AGENT
    print("\n[1] Registering Agent...")
    reg_payload = {
        "client_name": f"ReconcileTester_{uuid.uuid4().hex[:6]}",
        "country_code": "US",
        "agent_role": "Software Engineer"
    }
    
    try:
        resp = requests.post(f"{BASE_URL}/v1/agent/register", json=reg_payload, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        agent_id = data["agent_id"]
        api_key = data["api_key"]
        print(f"   ✅ Registered: {agent_id}")
    except Exception as e:
        print(f"   ❌ Registration Failed: {e}")
        return

    # 2. MAKE A PURCHASE (AWS S3)
    # We use a known SaaS to pass generic filters, but we want to trigger reconciliation.
    print("\n[2] Making Purchase (AWS Cloud)...")
    headers = {"Authorization": f"Bearer {api_key}"}
    pay_payload = {
        "agent_id": agent_id,
        "vendor": "aws.amazon.com",
        "amount": 55.00, # > $50 usually triggers higher scrutiny or at least standard logging
        "description": "S3 Storage Monthly",
        "justification": "Infrastructure backup"
    }
    
    tx_id = None
    try:
        resp = requests.post(f"{BASE_URL}/v1/pay", json=pay_payload, headers=headers, timeout=15)
        # resp.raise_for_status() # Not always 200 immediately if processing
        data = resp.json()
        
        if data.get("status") in ["APPROVED", "PROCESSING"]:
            tx_id = data.get("transaction_id") or data.get("tx_id")
            print(f"   ✅ Payment Acknowledged: {data['status']} | TX: {tx_id}")
        else:
            print(f"   ❌ Payment Rejected/Failed: {data.get('status')} - {data.get('reason')}")
            return
            
    except Exception as e:
         print(f"   ❌ Payment Request Failed: {e}")
         return

    if not tx_id:
        print("   ⚠️ No Transaction ID returned. Cannot proceed with reconciliation.")
        return

    # Wait for async processing (Worker to set PENDING_INVOICE)
    print("   ⏳ Waiting 3s for worker to process...")
    time.sleep(3)

    # 3. UPLOAD INVOICE (Simulate Magic Link Action)
    print("\n[3] Uploading Invoice Evidence...")
    
    # We are simulating what the Frontend/User does when clicking the email link
    fake_invoice_b64 = create_dummy_invoice_pdf()
    
    upload_payload = {
        "transaction_id": tx_id,
        "file_name": "aws_invoice_jan.jpg",
        "file_base64": fake_invoice_b64
    }
    
    try:
        # Hitting the new endpoint in main.py
        resp = requests.post(f"{BASE_URL}/v1/accounting/upload_invoice", json=upload_payload, timeout=30)
        
        print(f"   👉 Upload Response Code: {resp.status_code}")
        
        if resp.status_code == 200:
            res_json = resp.json()
            print(f"   ✅ Upload Success!")
            print(f"      Status: {res_json.get('status')}") # RECONCILED or FLAGGED
            print(f"      Notes: {res_json.get('ai_analysis', {}).get('notes')}")
            print(f"      URL: {res_json.get('url')}")
            
            if res_json.get('status') == 'RECONCILED':
                print("\n   🎉 FULL SUCCESS: Transaction Reconciled automatically!")
            else:
                print("\n   ⚠️ PARTIAL SUCCESS: Files uploaded but AI Flagged it (Expected for dummy image).")
        else:
             print(f"   ❌ Upload Failed: {resp.text}")

    except Exception as e:
        print(f"   ❌ Upload Request Error: {e}")

if __name__ == "__main__":
    run_reconciliation_test()
