import os
import json
import time
import base64
import base64
import requests
import uuid
from urllib.parse import urlparse
from datetime import datetime, timedelta
from loguru import logger


class ACPClient:
    """
    Client for the Agentic Commerce Protocol (ACP) - RFC 2025-12-11.
    Implements the "Checkout World" (Cart) and "Money World" (Delegate Payment) split.
    """

    def __init__(self, identity_manager):
        self.identity = identity_manager
        # Specific RFC Versions
        self.CHECKOUT_API_VERSION = "2025-12-11"
        self.DELEGATE_API_VERSION = "2025-09-29"
        self.DEFAULT_TIMEOUT = 10 

    def discover(self, vendor_url: str) -> dict:
        """
        Step 1: DISCOVERY.
        Checks for .well-known/agentic-commerce configuration.
        """
        try:
            parsed = urlparse(vendor_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            discovery_url = f"{base_url}/.well-known/agentic-commerce"
            
            logger.debug(f"🔎 [ACP] Discovering at {discovery_url}")
            resp = requests.get(discovery_url, timeout=3.0)
            
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception:
            return None

    # =========================================================
    # WORLD 1: CHECKOUT API (Negotiation & Context)
    # =========================================================
    
    def create_checkout_session(self, api_base: str, agent_id: str, items: list) -> dict:
        """
        RFC Phase A: Create Session.
        POST /checkout_sessions
        """
        url = f"{api_base}/checkout_sessions"
        
        # Spec 2025-12-11: 'items' list of {id, quantity}, and 'buyer' object.
        # items input assumed to be internal format: [{"sku":..., "quantity":...}]
        spec_items = [{"id": i["sku"], "quantity": i["quantity"]} for i in items]
        
        payload = {
            # REMOVED "mode": "payment" per strict RFC
            "items": spec_items, 
            "buyer": {
                "email": f"agent_{agent_id}@agentpay.ai",
                "first_name": "Agent",
                "last_name": agent_id[:8]
            }
        }
        
        headers = self._build_headers(agent_id, "POST", url, payload, api_version=self.CHECKOUT_API_VERSION)
        
        resp = self._request("POST", url, payload, headers)
        return resp.json() # Returns 'Authoritative Cart State'


    def update_session(self, api_base: str, session_id: str, agent_id: str, updates: dict) -> dict:
        """
        RFC Phase A (Part 2): Update Session (e.g. choose shipping).
        POST /checkout_sessions/{id}
        """
        url = f"{api_base}/checkout_sessions/{session_id}"
        headers = self._build_headers(agent_id, "POST", url, updates, api_version=self.CHECKOUT_API_VERSION)
        resp = self._request("POST", url, updates, headers)
        return resp.json()

    def complete_session(self, api_base: str, session_id: str, agent_id: str, payment_token: str) -> dict:
        """
        RFC Phase C: Execution.
        POST /checkout_sessions/{id}/complete
        """
        url = f"{api_base}/checkout_sessions/{session_id}/complete"
        
        payload = {
            "payment_data": {
                "token": payment_token, # The 'vt_...' token
                "provider": "stripe" # Or generic 'acp_delegate'
            }
        }
        
        headers = self._build_headers(agent_id, "POST", url, payload, api_version=self.CHECKOUT_API_VERSION)
        # Idempotency highly recommended here
        headers["Idempotency-Key"] = str(uuid.uuid4())
        
        resp = self._request("POST", url, payload, headers)
        return resp.json()

    # =========================================================
    # WORLD 2: DELEGATE PAYMENT API (The Money)
    # =========================================================

    def tokenize_payment(self, vault_url: str, session_id: str, total_amount: float, merchant_id: str, card_details: dict, agent_id: str) -> str:
        """
        RFC Phase B: Tokenization.
        POST /agentic_commerce/delegate_payment
        Exchanges Virtual PAN for a scoped 'SharedPaymentToken'.
        """
        url = f"{vault_url.rstrip('/')}/agentic_commerce/delegate_payment"
        
        payload = {
            "payment_method": {
                "type": "card",
                "number": card_details['number'],
                "exp_month": card_details['exp_month'],
                "exp_year": card_details['exp_year'],
                "cvc": card_details['cvc'],
                "display_card_funding_type": "credit",
                "card_number_type": "fpan", # REQUIRED
                "virtual": True,            # REQUIRED
                "metadata": {"source": "agentpay_core"} # REQUIRED
            },
            "allowance": {
                "reason": "one_time",
                "max_amount": int(total_amount * 100), # Cents
                "currency": "usd",
                "merchant_id": merchant_id,
                "checkout_session_id": session_id,
                "expires_at": (datetime.utcnow() + timedelta(minutes=15)).isoformat() + "Z" # REQUIRED
            },
            "risk_signals": [{
                "type": "agent_trust_score",
                "score": 99,
                "source": "agentpay_ai_guard"
            }],
            "metadata": { # REQUIRED Top-Level Metadata
                "transaction_source": "agentpay_core_v1",
                "agent_id": agent_id
            }
        }
        
        headers = self._build_headers(agent_id, "POST", url, payload, api_version=self.DELEGATE_API_VERSION)
        
        resp = self._request("POST", url, payload, headers)
        data = resp.json()
        
        # Expecting payment_data.token or similar
        return data.get("payment_data", {}).get("token") or data.get("token")


    # =========================================================
    # INTERNALS
    # =========================================================

    def _request(self, method, url, payload, headers):
        try:
            resp = requests.request(method, url, json=payload, headers=headers, timeout=self.DEFAULT_TIMEOUT)
            resp.raise_for_status()
            return resp
        except requests.exceptions.HTTPError as e:
            logger.error(f"❌ [ACP] HTTP Error {e.response.status_code}: {e.response.text}")
            raise e
        except Exception as e:
            logger.critical(f"❌ [ACP] Network Error: {e}")
            raise e

    def _build_headers(self, agent_id, method, url, payload, api_version):
        body_str = json.dumps(payload)
        parsed = urlparse(url)
        path_qty = parsed.path
        if parsed.query: path_qty += f"?{parsed.query}"

        # Detached Signature construction
        headers = {
            "API-Version": api_version,
            "Content-Type": "application/json",
            "X-Agent-ID": agent_id,
            "X-Request-Timestamp": str(int(time.time()))
        }
        
        # Call Identity for signature
        # Format: "header-list: value\n...content" (Standard HTTP Sig) OR specific ACP detached
        # User said: "Detached signature over canonical JSON"
        # We will sign the Body + Timestamp + Path
        canonical = f"{method}|{path_qty}|{headers['X-Request-Timestamp']}|{body_str}"
        signature = self.identity.sign_payload(agent_id, canonical)
        
        headers["Signature"] = f"t={headers['X-Request-Timestamp']},v1={signature}"
        return headers
