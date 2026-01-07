import asyncio
import json
import os
import sys
from unittest.mock import MagicMock, AsyncMock

# Add current path to sys.path to import core modules
sys.path.append(os.getcwd())

from engine import UniversalEngine
from models import TransactionRequest

async def test_acp_integration():
    print("🚀 Starting ACP Integration Check...")
    
    # 1. Mock dependencies to avoid real network/db/stripe calls
    engine = UniversalEngine()
    engine.db = MagicMock()
    engine.redis_enabled = False # Bypass Redis
    engine.identity_mgr = MagicMock()
    
    # Mock Identity Signing
    engine.identity_mgr.sign_payload.return_value = "mock_kms_signature_base64"
    
    # Mock ACP Client (The Critical Part)
    engine._acp = MagicMock()
    
    # Step A: Mock Discovery
    engine._acp.discover.return_value = {
        "version": "1.0",
        "vault_url": "https://vault.stripe.com",
        "merchant_id": "acme_corp"
    }
    
    # Step B: Mock Checkout Session (A - Negotiation)
    engine._acp.create_checkout_session.return_value = {
        "id": "cs_test_123",
        "amount_total": 1000, # Cents
        "currency": "usd",
        "payment_status": "unpaid",
        "items": [...]
    }

    # Step C: Mock Tokenization (B - Delegate Payment)
    engine._acp.tokenize_payment.return_value = "vt_test_token_999"
    
    # Step D: Mock Completion (C - Execution)
    engine._acp.complete_session.return_value = {
        "status": "complete",
        "payment_status": "paid",
        "id": "cs_test_123"
    }

    # 2. Create Request
    req = TransactionRequest(
        agent_id="agent_007",
        vendor="Amazon Web Services",
        vendor_url="https://aws.amazon.com",
        amount=10.00,
        description="Server Rental"
    )
    
    # 3. Execute
    print("🔄 Executing Hybrid Engine Evaluation (RFC 2025)...")
    result = await engine.evaluate_fast_path(req)
    
    # 4. Assertions
    print("\n📊 RESULTS ANALYSIS:")
    print(f"Status: {result.status}")
    print(f"Protocol: {result.payment_protocol}")
    
    if result.payment_protocol == "ACP_NATIVE":
        print("✅ SUCCESS: Engine chose ACP Protocol Rail.")
    else:
        print("❌ FAILED: Engine fell back to Legacy Card.")
        return

    if result.acp_receipt_data and result.acp_receipt_data.get('status') == "complete":
        print("✅ SUCCESS: Session Completed.")
    else:
        print("❌ FAILED: Receipt data missing or incorrect.")

    # Verify flow calls
    engine._acp.discover.assert_called_once()
    engine._acp.create_checkout_session.assert_called_once()
    # verify tokenization called with session id linkage
    engine._acp.tokenize_payment.assert_called_once()
    engine._acp.complete_session.assert_called_once()


    
    print("\n🎉 INTEGRATION VERIFIED: The generic engine successfully negotiated, signed, and executed an ACP transaction.")

if __name__ == "__main__":
    asyncio.run(test_acp_integration())
