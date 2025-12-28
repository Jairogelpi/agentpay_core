# 🛡️ AgentPay: The Financial OS for Autonomous AI Agents

**AgentPay** is the first banking and legal infrastructure designed specifically for AI Agents. It provides a unified API to handle Money, Identity, Security, and Law, allowing agents to operate autonomously in the real world.

## 🚀 Features (Unbreakable Edition)

### 1. 💳 Autonomous Finance
- **Payments**: `agent.pay(vendor, amount)` with AI Guard rails.
- **Streaming**: `agent.stream_pay()` for high-frequency micropayments.
- **Invoicing**: `agent.get_invoice(id)` to download PDFs automatically.
- **Credit**: `agent.check_credit_status()` for Gold/Platinum tier lines.

### 2. 👻 Ghost Identity Protocol
- **Email & Proxies**: Private Brevo Inbound Parsing and Residential Proxies.
- **Real SMS**: `agent.check_sms(id)` and `agent.wait_for_otp(channel="sms")` using Twilio.
- **Session Persistence**: `agent.save_session_state()` and `agent.recover_identities()` to maintain login cookies across reboots.

### 3. ⚖️ Legal & Security
- **Legal Wrapper**: `agent.sign_contract(hash)` signs via AgentPay DAO/LLC logic.
- **Fraud Reporting**: `agent.report_fraud()` and `agent.dispute_transaction()`.
- **Smart Webhooks**: Proactive notifications (`agent.set_webhook_url`) when humans approve pending payments.

## 📦 Installation & SDK Usage
No dashboard needed. Everything is programmatic.

```bash
pip install agentpay requests  # (Simulated)
```

```python
from agentpay import AgentPay

# 1. Initialize
agent = AgentPay(api_key="sk_live_...")

# 2. Top Up & Pay
agent.top_up(50.0) # SDK automatically injects agent_id
response = agent.pay("aws.amazon.com", 15.99, "Server hosting")

# 3. Handle 2FA (SMS)
identity = agent.create_identity(needs_phone=True)
code = agent.wait_for_otp(identity['identity_id'], channel="sms")

# 4. Save Session (Persist cookies)
agent.save_session_state(identity['identity_id'], navigator.cookies_dict)
```

## 🛠️ Deployment
- **Backend**: FastAPI + Supabase + Stripe + Twilio.
- **Env Vars Required**: `STRIPE_SECRET_KEY`, `SUPABASE_URL`, `SUPABASE_KEY`, `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `OPENAI_API_KEY`.

---
*Built with ❤️ for the Agentic Economy.*
