
import sys
import json
import os
import uuid
import time
from unittest.mock import MagicMock

# Environment
os.environ["OPENAI_API_KEY"] = "mock_key"
os.environ["SUPABASE_URL"] = "http://mock"
os.environ["SUPABASE_KEY"] = "mock"
os.environ["STRIPE_SECRET_KEY"] = "sk_test_mock"
os.environ["LEGAL_SECRET_KEY"] = "mock_legal_key"
os.environ["TWILIO_ACCOUNT_SID"] = "mock_sid"
os.environ["TWILIO_AUTH_TOKEN"] = "mock_token"

# Mock libs
sys.modules["openai"] = MagicMock()
sys.modules["stripe"] = MagicMock()
sys.modules["supabase"] = MagicMock()
# We need to mock the external modules imported by engine
sys.modules["webhooks"] = MagicMock()
sys.modules["notifications"] = MagicMock()
sys.modules["invoicing"] = MagicMock()
sys.modules["security_utils"] = MagicMock()

import arbitration
import engine as engine_module

# Setup AI Arbiter Mock
arbitration.client = MagicMock()
arbitration.ARBITER_ENABLED = True

# Setup Mock DB for Engine
class SmartMockDB:
    def __init__(self):
        self.wallet_data = {"balance": 1000.0, "agent_id": "escrow_agent"}
    def table(self, name): return self
    def select(self, *args, **kwargs): return self
    def eq(self, *args, **kwargs): return self
    def execute(self): return type('obj', (object,), {'data': [self.wallet_data]})
    def update(self, data): 
        if "balance" in data: self.wallet_data['balance'] = data['balance']
        return self
    def insert(self, *args, **kwargs): return self

eng = engine_module.UniversalEngine()
eng.db = SmartMockDB()

print("--- 1. Testing Escrow Creation (Locking Funds) ---")
res_create = eng.create_escrow_transaction("escrow_agent", "suspicious-vendor.com", 200.0, "API Access")
print(f"Creation Status: {res_create['status']}")
print(f"New Balance (Should be 800): {eng.db.wallet_data['balance']}")

if res_create['status'] == "ESCROW_CREATED" and eng.db.wallet_data['balance'] == 800.0:
    print("✅ Funds Locked Successfully")
else:
    print("❌ Failed to lock funds")


print("\n--- 2. Testing AI Judge Arbitration (Winning Case) ---")
# Simulate Agent submitting evidence of scam
claim = "Vendor sent an empty file instead of the dataset."
evidence = "File hash: 0000000 (Empty). Logs: 'Download failed: 0 bytes'."

# Mock AI Response to favor Agent
mock_judgment = MagicMock()
mock_judgment.choices[0].message.content = json.dumps({
    "verdict": "REFUND_AGENT",
    "confidence": 95,
    "judicial_opinion": "Evidence shows non-delivery of promised goods. Vendor failed to rebut."
})
arbitration.client.chat.completions.create.return_value = mock_judgment

res_dispute = eng.raise_escrow_dispute("escrow_agent", res_create['transaction_id'], claim, evidence)

print(f"Verdict: {res_dispute.get('status')}")
print(f"Opinion: {res_dispute.get('judicial_opinion')}")

if res_dispute['status'] == "REFUNDED":
    print("✅ AI Judge correctly refunded the agent")
else:
    print(f"❌ Wrong verdict: {res_dispute}")

print("\n--- 3. Testing AI Judge (Losing Case) ---")
# Simulate buyer's remorse
claim2 = "I don't like the color of the dashboard."
evidence2 = "Screenshot included."

# Mock AI Response to favor Vendor
mock_judgment_loss = MagicMock()
mock_judgment_loss.choices[0].message.content = json.dumps({
    "verdict": "PAY_VENDOR",
    "confidence": 99,
    "judicial_opinion": "Subjective dissatisfaction is not grounds for refund. Product delivered as described."
})
arbitration.client.chat.completions.create.return_value = mock_judgment_loss

res_loss = eng.raise_escrow_dispute("escrow_agent", "tx_2", claim2, evidence2)

if res_loss['status'] == "DISPUTE_LOST":
    print("✅ AI Judge correctly rejected trivial claim")
else:
    print(f"❌ Failed to reject: {res_loss}")
