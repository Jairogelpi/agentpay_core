import sys
import os
import json

# Set fake env vars
os.environ["SUPABASE_URL"] = "http://test.com"
os.environ["SUPABASE_KEY"] = "test"
os.environ["STRIPE_SECRET_KEY"] = "test"

# Mock Modules
from unittest.mock import MagicMock
sys.modules["openai"] = MagicMock()
sys.modules["stripe"] = MagicMock() # Need to keep ref to this mock to check proxy
sys.modules["supabase"] = MagicMock()
sys.modules["webhooks"] = MagicMock()
sys.modules["notifications"] = MagicMock()
sys.modules["invoicing"] = MagicMock() # Mock invoicing too

# Mock security_utils AND specific function
sec_mock = MagicMock()
sys.modules["security_utils"] = sec_mock
# We need to ensure when engine imports check_domain_age, it gets our mock
# But since engine does "from security_utils import check_domain_age", we must set it on the module mock
sec_mock.check_domain_age.return_value = "MEDIUM_RISK"

# Mock ai_guard
ai_mock = MagicMock()
sys.modules["ai_guard"] = ai_mock
ai_mock.audit_transaction.return_value = {
    "decision": "APPROVED",
    "risk_score": 10,
    "anomaly_detected": False,
    "reason": "Mocked Approval"
}

import stripe # Import the mocked stripe

try:
    from engine import UniversalEngine
    from identity import IdentityManager

    # Smart Mock DB
    class SmartMockDB:
        def __init__(self):
            self.current_table = None
            self.data = []
            
        def table(self, name):
            self.current_table = name
            return self
            
        def select(self, *args, **kwargs): return self
        def eq(self, *args, **kwargs): return self
        def order(self, *args, **kwargs): return self
        def limit(self, *args, **kwargs): return self
        
        def execute(self):
            if self.current_table == "wallets":
                return type('obj', (object,), {'data': [{"balance": 1000.0, "agent_id": "test_agent", "owner_name": "Mr X"}]})
            elif self.current_table == "global_blacklist":
                return type('obj', (object,), {'data': []}) # No blacklist matches
            return type('obj', (object,), {'data': []})
            
        def update(self, *args, **kwargs): 
            return self
        def eq(self, *args, **kwargs): return self # Re-define to return self
        
    engine = UniversalEngine()
    engine.db = SmartMockDB()
    
    # Enable Invisible Mode manually if needed, but MEDIUM_RISK should trigger it.
    # We need to ensure IdentityManager.generate_digital_fingerprint is called.
    
    # Create Request
    from models import TransactionRequest
    req = TransactionRequest(agent_id="test_agent", vendor="newsite.com", amount=50.0, description="Test")
    
    print("--- Testing Invisible Mode Trigger ---")
    
    # Trigger Evaluate
    res = engine.evaluate(req)
    
    print(f"Result Status: {res.status}")
    print(f"Result Reason: {res.reason}")
    if hasattr(res, 'approval_link'): print(f"Approval Link: {res.approval_link}")
    
    # Verify Stripe Logic
    # Check if PaymentIntent.create was called with metadata
    calls = stripe.PaymentIntent.create.call_args_list
    if not calls:
        print("❌ Stripe create not called")
        sys.exit(1)
        
    args, kwargs = calls[0]
    metadata = kwargs.get('metadata', {})
    print(f"Stripe Metadata: {metadata}")
    
    if 'user_agent' in metadata and 'screen_res' in metadata:
        print("✅ Metadata injected (User-Agent present)")
    else:
        print("❌ Metadata missing User-Agent")
        sys.exit(1)

    # Note: Checking stripe.proxy is hard because it's reset. 
    # But if metadata is there, the Invisible Context was generated and passed.
    
    print("✅ Invisible Mode Verified")

except Exception as e:
    print(f"❌ Test Failed: {e}")
    sys.exit(1)
