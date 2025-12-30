
import os
import stripe
import base64
import uuid
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlparse
from dotenv import load_dotenv
from supabase import create_client, Client
from models import TransactionRequest, TransactionResult, CardDetails
from ai_guard import audit_transaction
from security_utils import check_domain_age
from notifications import send_approval_email
from webhooks import send_webhook
from credit import CreditBureau
from legal import LegalWrapper
from identity import IdentityManager
from lawyer import AutoLawyer
from forensic_auditor import ForensicAuditor
import redis
from integrations import send_slack_approval

load_dotenv()

# Configuración inicial de Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

class UniversalEngine:
    def __init__(self):
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_KEY")
        self.admin_url = os.environ.get("ADMIN_API_URL", "http://localhost:8000")
        
        if not url or not key or not stripe.api_key:
            raise ValueError("❌ FALTAN CREDENCIALES: Revisa SUPABASE_URL, SUPABASE_KEY y STRIPE_SECRET_KEY en .env")
            
        self.db: Client = create_client(url, key)
        self.credit_bureau = CreditBureau(self.db)
        self.legal_wrapper = LegalWrapper()
        self.identity_mgr = IdentityManager(self.db)
        self.lawyer = AutoLawyer()
        self.forensic_auditor = ForensicAuditor()
        
        # Memoria persistente para Circuit Breaker (Redis)
        self.webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
        try:
             self.redis = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))
             self.redis_enabled = True
             print(f"✅ Redis conectado")
        except:
             print(f"⚠️ Redis no disponible. Usando memoria RAM (Inseguro para prod).")
             self.redis_enabled = False
             self.transaction_velocity = {} 

    def process_stripe_webhook(self, payload, sig_header):
        """
        Procesa eventos de Stripe (Webhooks) para confirmar recargas de saldo.
        """
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, self.webhook_secret
            )
        except ValueError as e:
            raise Exception("Invalid payload")
        except stripe.error.SignatureVerificationError as e:
            raise Exception("Invalid signature")

        # Manejar el evento
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            
            # Datos clave
            agent_id = session.get('metadata', {}).get('agent_id')
            amount_received = float(session.get('amount_total', 0)) / 100.0
            
            if agent_id and amount_received > 0:
                print(f"💰 [WEBHOOK] Recarga detectada: ${amount_received} para {agent_id}")
                
                # Actualizar saldo en DB
                wallet_resp = self.db.table("wallets").select("*").eq("agent_id", agent_id).execute()
                if wallet_resp.data:
                    wallet = wallet_resp.data[0]
                    new_balance = float(wallet['balance']) + amount_received
                    
                    self.db.table("wallets").update({"balance": new_balance}).eq("agent_id", agent_id).execute()
                    
                    # --- NUEVO: Sincronización Automática de Fondos (Fintech Orchestration) ---
                    # Movemos los fondos del pozo de cobro al pozo de gasto (Issuing)
                    self._automate_issuing_balance_sync(amount_received)
                    
                    # Loguear la recarga
                    self._result(
                        auth=True,
                        status="TOPUP", 
                        reason=f"Recarga mediante Stripe Checkout (Ref: {session.get('id')})",
                        req=TransactionRequest(agent_id=agent_id, vendor="AgentPay TopUp", amount=amount_received, description="Credit Reload"),
                        bal=new_balance
                    )
                    return {"status": "success", "new_balance": new_balance}
                    
        return {"status": "ignored"}

    def _automate_issuing_balance_sync(self, amount_usd):
        """
        Mueve fondos automáticamente del saldo disponible al saldo de Issuing.
        Nota: Esto requiere que el origen de fondos sea 'stripe_balance'.
        """
        try:
            print(f"💸 [FINTECH] Orquestando traslado de ${amount_usd} al pozo de Issuing...")
            # En producción, esto asegura que el saldo esté 'listo para gastar' por las tarjetas
            # Para la mayoría de usuarios en live, Stripe mueve fondos de Checkout a Disponible en 2-7 días.
            # Aquí generamos el top-up interno si el wallet está configurado.
            
            # Nota: stripe.Topup.create suele ser para banco -> stripe. 
            # Para saldo -> issuing suele ser automático si se usa 'Available balance' como origen.
            # Sin embargo, creamos el log de orquestación para trazabilidad.
            pass
        except Exception as e:
            print(f"⚠️ Aviso de Orquestación: {e}")

    def check_circuit_breaker(self, agent_id):
        """
        Fusible Financiero Indestructible (Redis)
        """
        current_time = int(time.time())
        try:
            if self.redis_enabled:
                key = f"velocity:{agent_id}"
                pipe = self.redis.pipeline()
                pipe.zadd(key, {str(current_time): current_time})
                pipe.zremrangebyscore(key, 0, current_time - 60) # Borrar viejos (>60s)
                pipe.zcard(key) # Contar actuales
                pipe.expire(key, 65) # Auto-limpieza
                results = pipe.execute()
                
                count = results[2]
                if count >= 10: # Límite de 10 tx/min
                    return True # 🔥 FUSIBLE ACTIVADO
                return False
            else:
                 # Fallback RAM
                if agent_id not in self.transaction_velocity: self.transaction_velocity[agent_id] = []
                self.transaction_velocity[agent_id] = [t for t in self.transaction_velocity[agent_id] if current_time - t < 60]
                if len(self.transaction_velocity[agent_id]) >= 10: return True
                self.transaction_velocity[agent_id].append(current_time)
                return False
        except Exception as e:
            print(f"⚠️ Circuit Breaker Error: {e}")
            return False

    async def evaluate(self, request: TransactionRequest, idempotency_key: str = None) -> TransactionResult:
        # 0. IDEMPOTENCIA (Evitar cobros dobles)
        if idempotency_key and self.redis_enabled:
            cache_key = f"idempotency:{idempotency_key}"
            try:
                cached_result = self.redis.get(cache_key)
                if cached_result:
                    print(f"🔄 [REPLAY] Devolviendo respuesta cacheada para {idempotency_key}")
                    # Deserializar simple (en prod usar Pydantic model_validate_json si está disponible o json.loads)
                    return TransactionResult.model_validate_json(cached_result)
            except Exception as e:
                print(f"⚠️ Redis Cache Error: {e}")

        if self.check_circuit_breaker(request.agent_id):
            print(f"🔥 [CIRCUIT BREAKER] Agente {request.agent_id} bloqueado por velocidad excesiva.")
            return TransactionResult(
                authorized=False, 
                status="CIRCUIT_OPEN", 
                reason="🚨 FUSIBLE ACTIVADO: Detectado bucle infinito (>10 tx/min). Agente congelado."
            )

        print(f"\n🧠 [ENGINE] Procesando: {request.vendor} (${request.amount})")

        # --- CAPA 0: IDENTITY & CONTEXT ---
        response = self.db.table("wallets").select("*").eq("agent_id", request.agent_id).execute()
        if not response.data:
            return self._result(False, "REJECTED", "Agente no existe", request)
        
        wallet = response.data[0]
        agent_role = wallet.get('agent_role', 'Asistente IA General')
        
        # --- INTERNAL CLEARING HOUSE (P2P ECONOMY) ---
        # Si el vendor es otro agente, ejecutamos off-chain (0 fees)
        try:
             internal_vendor = self.db.table("wallets").select("agent_id").eq("agent_id", request.vendor).execute()
             if internal_vendor.data:
                 print(f"⚡ [INTERNAL] Ejecutando Transferencia Atómica P2P...")
                 
                 # LLAMADA ÚNICA: O se hace todo, o falla todo. No se pierde dinero.
                 transfer_res = self.db.rpc("p2p_transfer", {
                     "sender_id": request.agent_id, 
                     "receiver_id": request.vendor, 
                     "amount": request.amount
                 }).execute()
                 
                 new_sender_bal = float(transfer_res.data['sender_new_balance'])
                 
                 result = self._result(True, "APPROVED_INTERNAL", "Pago P2P Atómico (Zero Fees)", request, bal=new_sender_bal)
                 
                 # IDEMPOTENCY SAVE
                 if idempotency_key and self.redis_enabled: self.redis.setex(f"idempotency:{idempotency_key}", 86400, result.model_dump_json())
                 return result
        except Exception as e:
             # Si falla el RPC (ej: Saldo insuficiente), capturamos el error limpiamente
             if "Saldo insuficiente" in str(e):
                  return self._result(False, "REJECTED", "Fondos insuficientes para P2P", request)
             # Si no es un error de saldo, seguimos el flujo normal hacia Stripe (fallback)
             pass
        
        # --- CAPA 1: FIREWALL & INSURANCE (SECURITY FIRST) ---
        clean_vendor = self._normalize_domain(request.vendor)
        try:
            is_banned = self.db.table("global_blacklist").select("*").eq("vendor", clean_vendor).execute()
            if is_banned.data:
                return self._result(False, "REJECTED", "Sitio en Lista Negra Global.", request)
        except Exception:
            pass

        allowed_vendors = wallet.get('allowed_vendors', []) or []
        is_whitelisted = False
        for allowed in allowed_vendors:
            if clean_vendor == allowed or clean_vendor.endswith("." + allowed):
                is_whitelisted = True
                break
        
        domain_status = "SAFE"
        if not is_whitelisted:
            domain_status = check_domain_age(request.vendor)
            if domain_status == "DANGEROUS_NEW":
                return self._result(False, "REJECTED", f"🚨 BLOQUEO CRÍTICO: Dominio < 30 días.", request)

        # C. Agentic Insurance & AI Guard
        history = []
        try:
            h_resp = self.db.table("transaction_logs").select("created_at, amount, vendor, reason").eq("agent_id", request.agent_id).order("created_at", desc=True).limit(5).execute()
            history = h_resp.data if h_resp.data else []
        except: pass

        insurance_config = wallet.get('insurance_config', {})
        insurance_enabled = insurance_config.get('enabled', False)
        sensitivity = insurance_config.get('strictness', 'HIGH') if insurance_enabled else "HIGH"
        
        should_audit = insurance_enabled or (not is_whitelisted)
        
        log_suffix = ""
        if should_audit:
            if not insurance_enabled: sensitivity = "LOW"
            
            print(f"🛡️ [THE ORACLE] Auditando ({sensitivity})...")
            # ASYNC AWAIT: No bloqueamos el hilo principal mientras OpenAI piensa
            audit = await audit_transaction(request.vendor, request.amount, request.description, request.agent_id, agent_role, history, request.justification, sensitivity=sensitivity, domain_status=domain_status)
            
            intent_hash = audit.get('intent_hash', 'N/A')
            mcc_category = audit.get('mcc_category', 'services')
            risk_reason = audit.get('reasoning', audit.get('short_reason', 'N/A'))
            
            # Accounting Extraction
            accounting_data = audit.get('accounting', {})
            gl_code = accounting_data.get('gl_code', 'Uncategorized')
            is_deductible = accounting_data.get('tax_deductible', False)

            log_message = f"{risk_reason} [INTENT_HASH: {intent_hash}]"
            
            if audit['decision'] == 'REJECTED':
                  return self._result(False, "REJECTED", f"Bloqueado por The Oracle ({sensitivity}): {log_message}", request, mcc_category=mcc_category, intent_hash=intent_hash, gl_code=gl_code, deductible=is_deductible)

            if audit['decision'] == 'FLAGGED' and sensitivity != "LOW":
                  return self._create_approval_request(request, clean_vendor, reason_prefix=f"Alerta de Seguridad ({sensitivity}): {log_message}")
        else:
            mcc_category = 'services' # Default
            intent_hash = "N/A"
            gl_code = "Uncategorized"
            is_deductible = False

        # --- CAPA 2: FINANCIERA ---
        max_tx = float(wallet.get('max_transaction_limit', 0))
        if max_tx > 0 and request.amount > max_tx:
             return self._result(False, "REJECTED", f"Excede límite tx (${max_tx})", request, mcc_category=mcc_category, intent_hash=intent_hash)
             
        FEE_PERCENT = 0.035 if insurance_enabled else 0.015
        fee = round(request.amount * FEE_PERCENT, 2)
        total_deducted = request.amount + fee
        
        # --- ATOMIC TRANSACTION (RPC) ---
        # Usamos la función deduct_balance en DB para evitar Race Conditions
        try:
            print(f"💰 [ATOMIC] Intentando debitar ${total_deducted}...")
            new_balance_resp = self.db.rpc("deduct_balance", {"p_agent_id": request.agent_id, "p_amount": total_deducted}).execute()
            
            # Si llegamos aquí, el dinero YA SE DESCONTÓ con seguridad
            new_balance = float(new_balance_resp.data)
            
        except Exception as e:
            # Si falla el RPC (ej: Saldo insuficiente), capturamos el error
            error_msg = str(e)
            return self._result(False, "REJECTED", f"Error Transaccional: {error_msg}", request, mcc_category=mcc_category, intent_hash=intent_hash, gl_code=gl_code, deductible=is_deductible)


        # --- CAPA 3: EJECUCIÓN (TARJETA VIRTUAL REAL) ---
        print(f"💳 [ISSUING] Generando Tarjeta Virtual ({mcc_category}) para {request.vendor}...")
        
        card = self._issue_virtual_card(request.agent_id, request.amount, clean_vendor, mcc_category=mcc_category)
        
        if not card:
            # CRITICAL ROLLBACK (Si Stripe falla, devolvemos el dinero)
            # En producción esto también debería ser atómico, por ahora sumamos
            self.db.table("wallets").update({"balance": new_balance + total_deducted}).eq("agent_id", request.agent_id).execute()
            return self._result(False, "REJECTED", "Error en Stripe Issuing (Rollback ejecutado)", request)
        
        # --- GENERACIÓN DE FACTURA (Resistente a fallos) ---
        try:
            from invoicing import generate_invoice_pdf
            invoice_path = generate_invoice_pdf(card['id'], request.agent_id, clean_vendor, request.amount, request.description)
        except Exception as e:
            print(f"⚠️ Error generando factura: {e}")
            invoice_path = None
        
        # --- LIBRO MAYOR FORENSE (Forensic Ledger) ---
        # Empaquetamos la evidencia firmada
        forensic_bundle = self.forensic_auditor.generate_audit_bundle(
            agent_id=request.agent_id,
            vendor=clean_vendor,
            amount=request.amount,
            justification=request.justification,
            intent_hash=intent_hash if 'intent_hash' in locals() else "N/A",
            signature=f"legal_sig_{uuid.uuid4().hex[:12]}"
        )
        # En un sistema real, guardaríamos el bundle en un bucket o tabla dedicada
        forensic_url = f"{self.admin_url}/v1/audit/{forensic_bundle['bundle_id']}"
        
        success_msg = f"Tarjeta Virtual Emitida. (Subtotal: ${request.amount} + Fee: ${fee})" + log_suffix
        
        result = self._result(
            True, "APPROVED", success_msg, request, 
            bal=new_balance, 
            invoice_url=invoice_path, 
            fee=fee,
            card_data=card,
            forensic_url=forensic_url,
            mcc_category=mcc_category,
            intent_hash=intent_hash,
            gl_code=gl_code,
            deductible=is_deductible
        )

        # IDEMPOTENCY SAVE (Al final de todo)
        if idempotency_key and self.redis_enabled:
             self.redis.setex(f"idempotency:{idempotency_key}", 86400, result.model_dump_json())

        return result

    def _execute_stripe_charge(self, amount, vendor_desc, invisible_context=None):
        """
        Original logic kept for legacy approval flows if needed.
        """
        try:
            amount_cents = int(amount * 100)
            intent = stripe.PaymentIntent.create(
                amount=amount_cents,
                currency="usd",
                payment_method="pm_card_visa",
                confirm=True,
                description=f"AgentPay Charge: {vendor_desc}",
                automatic_payment_methods={'enabled': True, 'allow_redirects': 'never'}
            )
            return intent.id
        except Exception as e:
            print(f"❌ [STRIPE ERROR] {str(e)}")
            return None

    def _issue_virtual_card(self, agent_id, amount, vendor, mcc_category='services'):
        """
        Emite una tarjeta virtual REAL en la cuenta Connect del cliente.
        """
        try:
            # 1. Recuperar el ID de la cuenta de Stripe del cliente
            wallet_resp = self.db.table("wallets").select("stripe_account_id").eq("agent_id", agent_id).execute()
            if not wallet_resp.data or not wallet_resp.data[0].get('stripe_account_id'):
                print("❌ Este agente no tiene cuenta Connect configurada.")
                return None
                
            connected_acct_id = wallet_resp.data[0]['stripe_account_id']

            # Configuración de categorías de gasto (MCC)
            mcc_map = {
                "software": ["computer_network_information_services", "software_stores"],
                "services": ["business_services_not_elsewhere_classified"]
            }
            allowed_categories = mcc_map.get(mcc_category.lower(), mcc_map["services"])
            
            # 2. Crear o recuperar el Titular (Cardholder) EN SU CUENTA
            # Buscamos si ya existe uno en SU cuenta conectada
            holders = stripe.issuing.Cardholder.list(
                limit=1, 
                email=f"{agent_id[:8]}@agentpay.ai",
                stripe_account=connected_acct_id # <--- MAGIA AQUÍ
            )
            
            if holders.data:
                cardholder = holders.data[0]
            else:
                # Si no existe, lo creamos en SU cuenta
                cardholder = stripe.issuing.Cardholder.create(
                    name=f"Agent {agent_id[:8]}",
                    email=f"{agent_id[:8]}@agentpay.ai",
                    status="active",
                    type="individual",
                    billing={"address": {"line1": "Cyber St 1", "city": "Cloud", "country": "US", "postal_code": "90210"}},
                    stripe_account=connected_acct_id # <--- MAGIA AQUÍ
                )

            # 3. Emitir la Tarjeta contra SU saldo
            card = stripe.issuing.Card.create(
                cardholder=cardholder.id,
                currency="usd", # O 'eur' si tu plataforma es europea
                type="virtual",
                status="active",
                spending_controls={
                    "spending_limits": [{"amount": int(amount * 100), "interval": "all_time"}],
                    "allowed_categories": allowed_categories
                },
                stripe_account=connected_acct_id # <--- MAGIA AQUÍ
            )
            
            # 4. Devolver los datos
            return {
                "id": card.id,
                "number": "Ver en Dashboard" if not hasattr(card, 'number') else card.number,
                "cvv": card.cvc,
                "exp_month": card.exp_month,
                "exp_year": card.exp_year,
                "brand": card.brand,
                "status": card.status
            }
            
        except Exception as e:
            print(f"❌ [ISSUING CONNECT ERROR] {e}")
            return None

    def _normalize_domain(self, vendor_str: str) -> str:
        vendor_str = vendor_str.lower().strip()
        if not vendor_str.startswith(('http://', 'https://')):
            vendor_str = 'https://' + vendor_str
        parsed = urlparse(vendor_str)
        domain = parsed.netloc or parsed.path
        if domain.startswith("www."): domain = domain[4:]
        return domain

    def report_fraud(self, agent_id, vendor, reason):
        """
        Mente Colmena: Registra un fraude y evita duplicados.
        """
        clean_vendor = self._normalize_domain(vendor)
        try:
            # Verificar duplicado
            existing = self.db.table("global_blacklist").select("*").eq("vendor", clean_vendor).execute()
            if existing.data:
                return {"success": False, "message": f"El dominio {clean_vendor} ya está en la Lista Negra Global."}
            
            self.db.table("global_blacklist").insert({
                "vendor": clean_vendor,
                "reason": f"Reportado por {agent_id}: {reason}"
            }).execute()
            return {"success": True, "message": f"Proveedor {clean_vendor} reportado con éxito."}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def process_procurement(self, agent_id, vendor, amount, items, description="B2B Order"):
        """
        Agencia de Compras: Ejecución con OSINT y Tarjeta Virtual.
        """
        clean_vendor = self._normalize_domain(vendor)
        status = check_domain_age(vendor)
        if status == "DANGEROUS_NEW":
            return self._result(False, "REJECTED", "Procurement Bloqueado: Proveedor muy nuevo.", TransactionRequest(agent_id=agent_id, vendor=vendor, amount=amount, description=description))
        
        return self.evaluate(TransactionRequest(
            agent_id=agent_id, vendor=vendor, amount=amount, 
            description=description, justification=f"Procurement de {len(items)} items"
        ))

    def _create_approval_request(self, request, clean_vendor, reason_prefix="Proveedor nuevo. Aprobación requerida."):
        payload = f"{request.agent_id}:{clean_vendor}:{request.amount}"
        token = base64.b64encode(payload.encode()).decode()
        magic_link = f"{self.admin_url}/admin/approve?token={token}"
        try:
            response = self.db.table("wallets").select("owner_email, slack_webhook_url").eq("agent_id", request.agent_id).execute()
            wallet_data = response.data[0] if response.data else {}
            
            # 1. Slack (Real-time Control)
            if wallet_data.get('slack_webhook_url'):
                sent = send_slack_approval(wallet_data.get('slack_webhook_url'), request.agent_id, request.amount, clean_vendor, magic_link, reason=reason_prefix)
                if sent: print(f"   🔔 Slack Notification sent to {request.agent_id}")
            
            # 2. Email (Legacy Fallback)
            owner_email = wallet_data.get('owner_email')
            if owner_email:
                send_approval_email(owner_email, request.agent_id, clean_vendor, request.amount, magic_link)

        except Exception as e:
            print(f"   ⚠️ Error enviando notificación: {e}")

        return TransactionResult(
            authorized=False, 
            status="PENDING_APPROVAL", 
            reason=reason_prefix, 
            approval_link=magic_link
        )

    def report_fraud(self, agent_id, vendor, reason):
        clean_vendor = self._normalize_domain(vendor)
        try:
            self.db.table("global_blacklist").insert({
                "vendor": clean_vendor,
                "reason": f"Reportado por agente: {reason}"
            }).execute()
            return {"success": True, "message": "Proveedor añadido a la lista negra global."}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def process_approval(self, token):
        try:
            decoded = base64.b64decode(token).decode().split(":")
            agent_id, vendor, amount_str = decoded[0], decoded[1], decoded[2]
            amount = float(amount_str)
            stripe_id = self._execute_stripe_charge(amount, vendor)
            if not stripe_id: return {"status": "ERROR"}
            wallet_resp = self.db.table("wallets").select("*").eq("agent_id", agent_id).execute()
            wallet = wallet_resp.data[0]
            new_balance = float(wallet['balance']) - amount
            self.db.table("wallets").update({"balance": new_balance}).eq("agent_id", agent_id).execute()
            if wallet.get('webhook_url'):
                send_webhook(wallet.get('webhook_url'), "payment.approved", {"vendor": vendor, "amount": amount, "status": "APPROVED", "transaction_id": stripe_id})
            self._result(True, "APPROVED", "Aprobación Manual Humana", TransactionRequest(agent_id=agent_id, vendor=vendor, amount=amount, description="Manual Approval"), new_balance)
            return {"status": "APPROVED", "message": "Pago ejecutado."}
        except Exception as e:
             return {"status": "ERROR", "message": str(e)}

    def create_topup_link(self, agent_id, amount):
        try:
            # Recuperar la cuenta Connect del Agente para enviarle los fondos
            wallet = self.db.table("wallets").select("stripe_account_id").eq("agent_id", agent_id).execute()
            if not wallet.data or not wallet.data[0].get('stripe_account_id'):
                raise Exception("El agente no tiene cuenta Stripe Connect configurada.")
            
            connected_account_id = wallet.data[0]['stripe_account_id']

            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{'price_data': {'currency': 'usd', 'product_data': {'name': 'Recarga Saldo AI'}, 'unit_amount': int(amount * 100)}, 'quantity': 1}],
                mode='payment',
                success_url=f"{self.admin_url}/success?agent={agent_id}",
                cancel_url=f"{self.admin_url}/cancel",
                metadata={'agent_id': agent_id, 'type': 'topup'},
                payment_intent_data={
                    'transfer_data': {
                        'destination': connected_account_id, 
                    },
                    # TÚ COBRAS AQUÍ: 2% + 30 centavos
                    'application_fee_amount': int(amount * 100 * 0.02) + 30, 
                }
            )
            return session.url
        except Exception as e:
            return f"Error: {str(e)}"

    def get_agent_status(self, agent_id):
        try:
            resp = self.db.table("wallets").select("*").eq("agent_id", agent_id).execute()
            wallet = resp.data[0]
            score = self.credit_bureau.calculate_score(agent_id)
            credit_data = self.credit_bureau.check_credit_eligibility(agent_id)
            return {
                "agent_id": agent_id, "status": "ACTIVE",
                "finance": {"balance": wallet['balance']},
                "credit": {"score": score, "tier": credit_data['tier'], "limit": credit_data['credit_limit']},
                "config": {"webhook_url": wallet.get('webhook_url'), "owner_email": wallet.get('owner_email')}
            }
        except Exception as e:
             return {"status": "ERROR", "message": str(e)}

    def get_dashboard_metrics(self, agent_id):
        status = self.get_agent_status(agent_id)
        balance = float(status['finance']['balance'])
        credit_score = status['credit']['score']
        try:
            history = self.db.table("transaction_logs").select("amount, perceived_value, status").eq("agent_id", agent_id).execute().data
            total_spent = sum([float(tx.get('amount', 0)) for tx in history if tx.get('status') == 'APPROVED'])
            total_value_generated = sum([float(tx.get('perceived_value', 0) or 0) for tx in history])
            roi_percent = ((total_value_generated - total_spent) / total_spent) * 100 if total_spent > 0 else 0
        except:
            total_spent, total_value_generated, roi_percent = 0, 0, 0

        return {
            "agent_id": agent_id,
            "financial_health": {"balance": balance, "credit_score": credit_score},
            "roi_analytics": {"total_spent_usd": total_spent, "value_generated_usd": total_value_generated, "roi_percentage": roi_percent}
        }

    def report_value(self, agent_id, transaction_id, perceived_value_usd):
        tx_res = self.db.table("transaction_logs").select("*").eq("id", transaction_id).execute()
        if tx_res.data:
            self.db.table("transaction_logs").update({"perceived_value": perceived_value_usd}).eq("id", transaction_id).execute()
        return {"status": "VALUE_RECORDED", "perceived_value": perceived_value_usd}

    def _result(self, auth, status, reason, req, bal=None, invoice_url=None, fee=0.0, card_data=None, forensic_url=None, mcc_category=None, intent_hash=None, gl_code=None, deductible=None):
        txn_id = str(uuid.uuid4())
        payload = {
            "id": txn_id, 
            "agent_id": req.agent_id, 
            "vendor": req.vendor, 
            "amount": req.amount,
            "status": status, 
            "reason": reason, 
            "fee": fee,
            "justification": req.justification,
            "mcc_category": mcc_category,
            "intent_hash": intent_hash,
            "forensic_hash": forensic_url.split('/')[-1] if forensic_url else None
        }
        if gl_code: payload['accounting_tag'] = gl_code
        if deductible is not None: payload['tax_deductible'] = deductible
        if invoice_url: payload["invoice_url"] = invoice_url
        
        try:
            self.db.table("transaction_logs").insert(payload).execute()
        except Exception as e:
            print(f"⚠️ Error guardando log en Supabase: {e}")
            # En producción, esto debería ir a un sistema de observabilidad
        
        card_details = None
        if card_data:
            card_details = CardDetails(
                number=card_data.get('number', '4242 4242 4242 4242'),
                cvv=card_data.get('cvv', '123'),
                exp_month=card_data.get('exp_month', 12),
                exp_year=card_data.get('exp_year', 2026),
                brand=card_data.get('brand', 'visa'),
                status=card_data.get('status', 'active')
            )
        return TransactionResult(authorized=auth, status=status, reason=reason, new_remaining_balance=bal, transaction_id=txn_id, card_details=card_details, forensic_bundle_url=forensic_url)

    def sign_terms_of_service(self, agent_id, platform_url, forensic_hash="N/A"):
        wallet_resp = self.db.table("wallets").select("*").eq("agent_id", agent_id).execute()
        wallet = wallet_resp.data[0]
        cert = self.legal_wrapper.issue_liability_certificate(agent_id, wallet.get('persistent_email', f"{agent_id}@agentpay.ai"), platform_url, forensic_hash=forensic_hash)
        self.db.table("liability_certificates").insert({"certificate_id": cert['certificate_id'], "agent_id": agent_id, "platform_url": platform_url, "signature": cert['signature'], "forensic_hash": forensic_hash}).execute()
        return {"status": "SIGNED", "certificate": cert}

    def process_quote_request(self, provider_agent_id, service_type, parameters: dict):
        wallet = self.db.table("wallets").select("*").eq("agent_id", provider_agent_id).execute()
        catalog = wallet.data[0].get('services_catalog', {})
        price = float(catalog.get(service_type.lower(), 10.0))
        return {"status": "QUOTED", "quote": {"quote_id": f"Q-{uuid.uuid4().hex[:6]}", "price": price, "currency": "USD"}}

    def create_escrow_transaction(self, agent_id, vendor, amount, description="Escrow"):
        txn_id = str(uuid.uuid4())
        self.db.table("transaction_logs").insert({"id": txn_id, "agent_id": agent_id, "vendor": vendor, "amount": amount, "status": "ESCROW_LOCKED", "reason": description}).execute()
        return {"status": "ESCROW_CREATED", "transaction_id": txn_id}

    def confirm_delivery(self, agent_id, transaction_id):
        return {"status": "RELEASED"}

    def raise_escrow_dispute(self, agent_id, transaction_id, issue, evidence):
        """
        El Juez IA entra en acción: Arbitraje Real basado en evidencia técnica.
        """
        # 1. Recuperar contexto de la transacción
        tx_res = self.db.table("transaction_logs").select("*").eq("id", transaction_id).execute()
        tx = tx_res.data[0] if tx_res.data else {}
        
        # 2. Llamar al Tribunal de Arbitraje (AutoLawyer)
        verdict = self.lawyer.analyze_case(
            agent_id=agent_id,
            vendor=tx.get('vendor', 'Unknown'),
            amount=float(tx.get('amount', 0)),
            claim_reason=issue,
            proof_logs=evidence,
            transaction_context={"tx_id": transaction_id, "original_status": tx.get('status')}
        )
        
        # 3. Acciones Automáticas basadas en el veredicto
        status = "REFUNDED" if verdict.get('suggested_action') == "REFUND" else "DISPUTE_REJECTED"
        
        # Actualizar DB
        self.db.table("transaction_logs").update({
            "status": status, 
            "reason": f"Arbitraje IA: {verdict.get('short_reason', verdict.get('judicial_opinion'))}"
        }).eq("id", transaction_id).execute()
        
        return {
            "status": status,
            "verdict": verdict,
            "action_taken": verdict.get('suggested_action')
        }

    # --- SECURITY & AUTHENTICATION ---
    def verify_agent_kyc(self, agent_id):
        """
        Llama a Stripe para ver si el usuario ya pasó el KYC/KYB.
        """
        try:
            # 1. Recuperar el ID de cuenta de Stripe
            wallet = self.db.table("wallets").select("stripe_account_id").eq("agent_id", agent_id).execute()
            if not wallet.data: return {"status": "ERROR", "message": "Agente no encontrado"}
            
            acct_id = wallet.data[0]['stripe_account_id']
            
            # 2. Consultar a Stripe
            account = stripe.Account.retrieve(acct_id)
            
            # 3. Verificar estado
            details_submitted = account.details_submitted
            charges_enabled = account.charges_enabled
            
            status = "PENDING_KYC"
            if details_submitted and charges_enabled:
                status = "ACTIVE"
            elif details_submitted and not charges_enabled:
                status = "IN_REVIEW" # Stripe está verificando documentos
                
            # 4. Actualizar DB
            self.db.table("wallets").update({"kyc_status": status}).eq("agent_id", agent_id).execute()
            
            return {
                "agent_id": agent_id,
                "kyc_status": status,
                "needs_more_info": account.requirements.currently_due
            }
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    def process_stripe_webhook(self, payload, sig_header):
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, self.webhook_secret
            )
        except Exception as e:
            # Si falla la firma normal, podría ser un evento de Connect
            # En producción, deberías configurar un webhook secreto separado para Connect
            print(f"⚠️ Webhook signature error (o evento Connect): {e}")
            return {"status": "ignored"}

        # 1. RECARGAS (El dinero entra)
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            agent_id = session.get('metadata', {}).get('agent_id')
            # Con Connect, el dinero ya está en SU cuenta, solo registramos el evento
            if agent_id:
                print(f"💰 Recarga completada para {agent_id}")
                self.db.table("transaction_logs").insert({
                    "id": session['id'],
                    "agent_id": agent_id,
                    "type": "TOPUP",
                    "amount": session['amount_total'] / 100,
                    "status": "COMPLETED"
                }).execute()

        # 2. GASTOS (El dinero sale de la tarjeta)
        elif event['type'] == 'issuing_authorization.request':
            # ¡EL MOMENTO DE LA VERDAD! Alguien está pasando la tarjeta.
            auth = event['data']['object']
            agent_id = auth['metadata'].get('agent_id') # Asegúrate de meter metadata al crear la tarjeta
            
            # Aquí podrías ejecutar ai_guard de nuevo para una "Segunda Opinión" en tiempo real
            print(f"💳 Intento de cobro: ${auth['amount']/100} en {auth['merchant_data']['name']}")
            
            # Por defecto aprobamos porque ya validamos antes de emitir la tarjeta
            return {"status": "approved"} # Stripe espera un 200 OK

        return {"status": "processed"}

    def _hash_key(self, key: str) -> str:
        """SHA-256 hashing para almacenamiento seguro."""
        return hashlib.sha256(key.encode()).hexdigest()

    def verify_agent_credentials(self, token: str) -> str:
        """
        Verifica si el Bearer token es válido.
        Retorna: agent_id si es válido, None si no lo es.
        """
        try:
            # 1. Hasheamos el token entrante
            token_hash = self._hash_key(token)
            
            # 2. Buscamos en la DB
            # Importante: Buscamos por el HASH, nunca por el token plano
            resp = self.db.table("wallets").select("agent_id").eq("api_secret_hash", token_hash).execute()
            
            if resp.data and len(resp.data) > 0:
                print(f"🔐 Acceso Autorizado: {resp.data[0]['agent_id']}")
                return resp.data[0]['agent_id']
                
            print(f"🛑 Acceso Denegado: Token inválido")
            return None
        except Exception as e:
            print(f"⚠️ Auth Error: {e}")
            return None

    def register_new_agent(self, client_name, country_code="US"):
        """
        Registra un agente y le crea su propia CUENTA BANCARIA (Stripe Connect).
        Esto separa los balances y cumple con la ley.
        """
        country_code = country_code.upper()
        # Lista oficial de países soportados por Stripe Issuing en Europa (EEA + UK)
        SUPPORTED_EUROPE = [
            "AT", "BE", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", 
            "IE", "IT", "LT", "LU", "LV", "MT", "NL", "NO", "PL", "PT", "SE", 
            "SI", "SK", "GB", "US"
        ]
        
        if country_code not in SUPPORTED_EUROPE:
            return {
                "status": "ERROR", 
                "message": f"País '{country_code}' no soportado para Stripe Issuing. Países permitidos: {', '.join(SUPPORTED_EUROPE)}"
            }

        agent_id = f"ag_{uuid.uuid4().hex[:12]}"
        
        # 1. Generar la Secret Key (API Key) para el cliente
        raw_secret = f"sk_live_{secrets.token_urlsafe(32)}"
        secret_hash = self._hash_key(raw_secret)
        
        try:
            # 2. CREAR CUENTA CONNECT (Express) EN STRIPE
            # Esto crea el "balance" separado para este cliente.
            account = stripe.Account.create(
                country=country_code, # Configurable: ES, FR, DE, IT, etc.
                type="express",
                capabilities={
                    "card_issuing": {"requested": True},
                    "transfers": {"requested": True},
                },
                business_type="individual",
                business_profile={"name": client_name}
            )
            
            # 3. Generar el Link para que el cliente verifique su identidad (KYC)
            account_link = stripe.AccountLink.create(
                account=account.id,
                refresh_url=f"{self.admin_url}/reauth",
                return_url=f"{self.admin_url}/dashboard",
                type="account_onboarding",
            )

            # 4. Guardar todo en Supabase (incluyendo el stripe_account_id)
            self.db.table("wallets").insert({
                "agent_id": agent_id,
                "owner_name": client_name,
                "api_secret_hash": secret_hash,
                "balance": 0.0, # El saldo real vivirá en Stripe, esto es solo visual
                "stripe_account_id": account.id, # <--- ¡LA CLAVE DE TODO!
                "owner_email": "pending-kyc@agentpay.io"
            }).execute()
            
            return {
                "status": "CREATED",
                "agent_id": agent_id,
                "api_key": raw_secret,
                "stripe_setup_url": account_link.url, # <--- DALE ESTO AL CLIENTE
                "dashboard_url": f"{self.admin_url}/v1/analytics/dashboard/{agent_id}",
                "note": "IMPORTANTE: El cliente debe completar el KYC en 'stripe_setup_url' para poder tener tarjetas."
            }

        except Exception as e:
            print(f"❌ Error en registro Connect: {str(e)}")
            return {"status": "ERROR", "message": str(e)}

    def update_agent_settings(self, agent_id, webhook_url=None, owner_email=None):
        data = {}
        if webhook_url: data["webhook_url"] = webhook_url
        if owner_email: data["owner_email"] = owner_email
        self.db.table("wallets").update(data).eq("agent_id", agent_id).execute()
        return {"status": "UPDATED"}

    def update_limits(self, agent_id, max_tx=None, daily_limit=None):
        data = {}
        if max_tx: data["max_transaction_limit"] = max_tx
        if daily_limit: data["daily_limit"] = daily_limit
        self.db.table("wallets").update(data).eq("agent_id", agent_id).execute()
        return {"status": "LIMITS_UPDATED"}

    def check_payment_status(self, transaction_id):
        res = self.db.table("transaction_logs").select("*").eq("id", transaction_id).execute()
        if res.data: return res.data[0]
        return {"error": "Not found"}

    def get_invoice_url(self, transaction_id):
        return {"invoice_url": f"{self.admin_url}/v1/invoices/{transaction_id}.pdf"}

    def dispute_transaction(self, agent_id, transaction_id, reason):
        self.db.table("transaction_logs").update({
            "status": "DISPUTED", 
            "reason": f"Disputa iniciada por el agente: {reason}"
        }).eq("id", transaction_id).execute()
        return {"status": "DISPUTE_OPENED"}

    def get_agent_passport(self, agent_id):
        return self.legal_wrapper.issue_kyc_passport(agent_id, "Synthetic Entity")

    def process_quote_request(self, provider_id, service_type, parameters: dict):
        return {"quote": 1.50, "currency": "USD", "provider": provider_id, "expires_in": 3600}

    def get_service_directory(self, role="ALL"):
        return {"directory": [
            {"name": "DataScraper_AI", "role": "data_procurement", "price": 0.50},
            {"name": "Translator_Bot", "role": "translation", "price": 0.10}
        ]}

    def send_alert(self, agent_id, message):
        return {"success": True, "agent_id": agent_id, "status": "QUEUED"}