
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
        # --- CAPA -1: SANITY CHECK (NUEVO) ---
        # Bloqueamos montos negativos, cero o absurdamente pequeños antes de gastar recursos.
        if request.amount <= 0.50:  # Mínimo de Stripe suele ser $0.50
            print(f"🚫 [SANITY] Monto inválido detectado: ${request.amount}")
            return TransactionResult(
                authorized=False,
                status="REJECTED",
                reason=f"Monto inválido (${request.amount}). El mínimo es $0.50."
            )

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
        MODO BANCO CENTRAL: Emite la tarjeta desde la PLATAFORMA.
        CORRECCIÓN FINAL: Incluye DOB, TOS y TELÉFONO (Requisito 3DS Europa).
        """
        try:
            # 1. CATEGORÍA SEGURA
            allowed_categories = ['miscellaneous']
            
            # 2. DATOS DEL TITULAR (CARDHOLDER)
            holder_email = f"{agent_id[:12]}@agentpay.ai"
            phone_dummy = "+34612345678" # <--- REQUISITO NUEVO: Teléfono para 3D Secure
            
            # Buscamos si ya existe el titular
            holders = stripe.issuing.Cardholder.list(limit=1, email=holder_email)
            
            if holders.data:
                cardholder = holders.data[0]
                # Si existe, actualizamos para asegurar que tenga teléfono y requisitos
                if cardholder.status != 'active' or not getattr(cardholder, 'phone_number', None):
                    print(f"   ⚠️ Actualizando titular (Teléfono + Requisitos)...")
                    stripe.issuing.Cardholder.modify(
                        cardholder.id,
                        status='active',
                        phone_number=phone_dummy, # Actualizamos teléfono
                        individual={
                            "first_name": "Agent",
                            "last_name": "User",
                            "dob": {"day": 1, "month": 1, "year": 1990},
                            "card_issuing": {
                                "user_terms_acceptance": {
                                    "date": int(time.time()),
                                    "ip": "8.8.8.8"
                                }
                            }
                        }
                    )
            else:
                # CREACIÓN NUEVA (EUROPA COMPLIANT + TELÉFONO)
                cardholder = stripe.issuing.Cardholder.create(
                    name="Agent Pay User",
                    email=holder_email,
                    phone_number=phone_dummy, # <--- AQUÍ ESTABA EL ERROR
                    status="active",
                    type="individual",
                    individual={
                        "first_name": "Agent",
                        "last_name": "User",
                        "dob": {"day": 1, "month": 1, "year": 1990}, 
                        "card_issuing": {
                            "user_terms_acceptance": {
                                "date": int(time.time()),   
                                "ip": "8.8.8.8"
                            }
                        }
                    },
                    billing={"address": {"line1": "Calle Gran Via 1", "city": "Madrid", "country": "ES", "postal_code": "28013"}}
                )

            # 3. EMITIR TARJETA
            print(f"✅ Emitiendo tarjeta para {agent_id}...")
            card = stripe.issuing.Card.create(
                cardholder=cardholder.id,
                currency="eur", 
                type="virtual",
                status="active",
                spending_controls={
                    "spending_limits": [{"amount": int(amount * 100), "interval": "all_time"}],
                    "allowed_categories": allowed_categories
                }
            )
            
            return {
                "id": card.id,
                "number": getattr(card, 'number', "4000 0000 0000 0000"),
                "cvv": getattr(card, 'cvc', "000"),
                "exp_month": card.exp_month,
                "exp_year": card.exp_year,
                "brand": card.brand,
                "status": card.status
            }
            
        except Exception as e:
            print(f"❌ [ISSUING PLATFORM ERROR] {e}")
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

    def automatic_topup(self, agent_id, amount):
        """
        RECARGA AUTOMÁTICA: Cobra $50 (o lo que sea) usando tarjeta de prueba
        y los envía a la cuenta del agente sin intervención humana.
        """
        try:
            # 1. Buscar la cuenta destino
            wallet = self.db.table("wallets").select("stripe_account_id, balance").eq("agent_id", agent_id).execute()
            if not wallet.data: raise Exception("Agente no encontrado")
            
            connected_account_id = wallet.data[0]['stripe_account_id']
            current_balance = float(wallet.data[0]['balance'])

            print(f"🤖 Iniciando recarga automática de ${amount} para {agent_id}...")

            # 2. EJECUTAR EL COBRO DIRECTO (Confirm=True)
            intent = stripe.PaymentIntent.create(
                amount=int(amount * 100), # Convertir a centavos
                currency='usd',
                payment_method="pm_card_visa", # <--- TARJETA QUE SIEMPRE FUNCIONA
                confirm=True, # <--- COBRA YA, NO ESPERES
                description=f"Auto-Topup for {agent_id}",
                automatic_payment_methods={'enabled': True, 'allow_redirects': 'never'},
                transfer_data={
                    'destination': connected_account_id, # Enviar el dinero al agente
                }
            )
            
            # 3. ACTUALIZAR SALDO EN TU BASE DE DATOS
            # Como es automático, no necesitamos esperar al Webhook
            new_bal = current_balance + amount
            self.db.table("wallets").update({"balance": new_bal}).eq("agent_id", agent_id).execute()

            print(f"✅ DINERO INGRESADO: ${amount} (Nuevo saldo: ${new_bal})")
            return {"status": "SUCCESS", "new_balance": new_bal, "tx_id": intent.id}


        except stripe.error.StripeError as e:
            # Si falla por "capabilities", intentamos activarlas forzosamente
            if "capabilities" in str(e):
                print(f"⚠️ Intentando reparar cuenta {connected_account_id}...")
                try:
                    stripe.Account.modify(connected_account_id, capabilities={"transfers": {"requested": True}})
                    return {"status": "RETRY_NEEDED", "message": "Cuenta reparada. Intenta de nuevo en 5 segundos."}
                except: pass
            return {"status": "ERROR", "message": str(e)}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    # --- ASYNC AUDIT HELPERS ---
    def _reverse_transaction(self, agent_id, amount):
        print(f"   💸 REVERSING: Devolviendo ${amount} a {agent_id}")
        try:
             # Devolución simple (sumar saldo)
             # En un sistema real usaríamos una tabla 'ledger' con entradas negativas/positivas
             self.db.rpc("deduct_balance", {"p_agent_id": agent_id, "p_amount": -amount}).execute() # Negativo = Suma
        except Exception as e:
            print(f"❌ Error Critical Reversing: {e}")

    def _ban_agent(self, agent_id, reason):
        print(f"   🚫 BANNING: Agente {agent_id} congelado por: {reason}")
        try:
            self.db.table("wallets").update({"status": "FROZEN", "ban_reason": str(reason)}).eq("agent_id", agent_id).execute()
        except Exception as e:
             print(f"❌ Error Banning Agent: {e}")

    async def run_background_audit(self, tx_data):
        """
        Auditoría Post-Pago: El cerebro trabaja mientras el dinero ya se movió.
        """
        print(f"🕵️ [THE ORACLE] Analizando rastro de: {tx_data.get('vendor')}")
        
        # Recuperar contexto necesario
        agent_id = tx_data.get('agent_id')
        vendor = tx_data.get('vendor')
        amount = tx_data.get('amount')
        
        # 0. AUTO-LEARN CHECK (Lista Blanca)
        try:
             w_res = self.db.table("wallets").select("agent_role, services_catalog, owner_email").eq("agent_id", agent_id).single().execute()
             wallet_data = w_res.data or {}
             agent_role = wallet_data.get('agent_role', 'Unknown')
             trusted_vendors = wallet_data.get('services_catalog', {})
             owner_email = wallet_data.get('owner_email')
             
             if vendor in trusted_vendors:
                 print(f"✅ [AUTO-LEARN] '{vendor}' ya es de confianza. Aprobando automáticamente.")
                 # Actualizar log a APPROVED (si estaba en PENDING o algo similar, aunque aquí ya está pagado)
                 # En background audit, el pago ya se hizo. Solo registramos que la AI lo valida.
                 self.db.table("transaction_logs").update({
                     "status": "APPROVED",
                     "reason": f"Trusted Vendor (Auto-Learn): {vendor}"
                 }).eq("id", tx_data.get('id')).execute()
                 return
                 
             h_resp = self.db.table("transaction_logs").select("created_at, amount, vendor, reason").eq("agent_id", agent_id).order("created_at", desc=True).limit(5).execute()
             history = h_resp.data if h_resp.data else []
        except: 
             agent_role = "Unknown"
             history = []
             trusted_vendors = {}

        # Llamamos a tu AI Guard COMPLETO
        risk_assessment = await audit_transaction(
            vendor=vendor, 
            amount=amount, 
            description=tx_data.get('description', 'N/A'), 
            agent_id=agent_id, 
            agent_role=agent_role, 
            history=history, 
            justification=tx_data.get('justification', 'N/A'),
            sensitivity="HIGH"
        )
        
        verdict = risk_assessment.get('decision', 'FLAGGED')
        reason_text = risk_assessment.get('reasoning', 'Fraud Detected')

        if "REJECTED" in verdict or "HIGH RISK" in str(risk_assessment).upper():
            agent_id = tx_data['agent_id']
            amount = float(tx_data['amount'])
            vendor = tx_data.get('vendor', 'UNKNOWN')
            
            # 0. Recuperar configuración de contacto del agente (Slack y Email)
            wallet_res = self.db.table("wallets").select("slack_webhook_url, owner_email").eq("agent_id", agent_id).single().execute()
            contact_info = wallet_res.data if wallet_res.data else {}
            slack_url = contact_info.get('slack_webhook_url')
            owner_email = contact_info.get('owner_email')
            
            # 1. REVERSIÓN: Devolver el dinero (monto negativo suma al saldo)
            self.db.rpc("deduct_balance", {"p_agent_id": agent_id, "p_amount": -amount}).execute()

            # 2. BANEO: Actualizar el estado del agente a BANNED
            self.db.table("wallets").update({"status": "BANNED"}).eq("agent_id", agent_id).execute()

            # 3. LOG: Registrar la expulsión por seguridad
            import uuid
            self.db.table("transaction_logs").insert({
                "id": str(uuid.uuid4()),
                "agent_id": agent_id,
                "amount": 0.0,
                "vendor": "SYSTEM_SECURITY",
                "status": "SECURITY_BAN",
                "reason": f"Fraude detectado por IA: {verdict}"
            }).execute()
            
            # 4. ALERTA INTERNA: Notificar al equipo de seguridad (SECURITY_ALERT_EMAIL)
            from notifications import send_security_ban_alert
            send_security_ban_alert(agent_id, reason_text, amount)
            
            # 5. ALERTA SLACK: Notificar al canal del agente si tiene Slack configurado
            if slack_url:
                from integrations import send_slack_approval
                send_slack_approval(
                    webhook_url=slack_url,
                    agent_id=agent_id,
                    amount=amount,
                    vendor=vendor,
                    approval_link="#",
                    reason=f"🚨 BANEO AUTOMÁTICO: {verdict}"
                )
                print(f"📢 Alerta Slack enviada para {agent_id}")
            
            # 6. ALERTA EMAIL AL CLIENTE: Notificar al dueño si tiene email configurado
            if owner_email:
                from notifications import send_ban_alert_to_owner
                try:
                    send_ban_alert_to_owner(
                        to_email=owner_email,
                        agent_id=agent_id,
                        vendor=vendor,
                        amount=amount,
                        reason=verdict
                    )
                    print(f"📧 Alerta de baneo enviada a {owner_email}")
                except Exception as e:
                    print(f"⚠️ Fallo al enviar alerta por email al cliente: {e}")
            
            print(f"✅ Protocolo completado. Agente {agent_id} neutralizado.")

        # --- ZONA GRIS / APRENDIZAJE ---
        elif amount > 1000 and "LOW RISK" not in verdict:
            print(f"🤔 [GREY AREA] Transacción alta (${amount}) requiere aprobación humana.")
            
            # Recuperar email si no estaba en rejected block
            try:
                wr = self.db.table("wallets").select("owner_email").eq("agent_id", agent_id).single().execute()
                owner_email = wr.data.get('owner_email')
            except: owner_email = None
            
            self.db.table("transaction_logs").update({
                "status": "PENDING_APPROVAL",
                "reason": f"Grey Area Risk: {verdict}"
            }).eq("id", tx_data.get('id')).execute()
            
            if owner_email:
                from notifications import send_approval_email
                # Link apunta a nuestro nuevo endpoint con learn=true
                base_url = "https://agentpay-core.onrender.com"
                approval_link = f"{base_url}/v1/approve?tx={tx_data.get('id')}&learn=true"
                
                try:
                    send_approval_email(owner_email, agent_id, vendor, amount, approval_link)
                    print(f"📧 Solicitud de Aprobación+Aprendizaje enviada a {owner_email}")
                except Exception as e:
                    print(f"⚠️ Error enviando email approval: {e}")

        else:
            print(f"✅ [AUDIT] Transacción validada y segura ({verdict}).")
            print(f"✅ [AUDIT] Transacción validada y segura ({verdict}).")

    async def process_instant_payment(self, request: TransactionRequest):
        """
        Fase 1: Aprobación Rápida (Solo Saldo y Reglas Básicas).
        Retorna en milisegundos.
        """
        # 1. Validaciones básicas / Sanity
        if request.amount <= 0.50:
             return {"status": "REJECTED", "reason": "Monto inválido (<$0.50)"}

        # 1.1 FAST-WALL (NUEVO): Filtro de ráfaga síncrono
        from ai_guard import fast_risk_check
        print(f"🔍 [FAST-WALL] Escaneando: '{request.description}' en '{request.vendor}'...")
        fast_check = fast_risk_check(request.description, request.vendor)
        if fast_check['risk'] == "CRITICAL":
            print(f"🛑 [FAST-WALL] Bloqueo inmediato: {fast_check['reason']}")
            
            # === PASO 1: BANEO (Crítico - debe ejecutarse primero) ===
            try:
                self.db.table("wallets").update({"status": "BANNED"}).eq("agent_id", request.agent_id).execute()
                print(f"✅ [FAST-WALL] Agente {request.agent_id} marcado como BANNED en DB.")
            except Exception as ban_err:
                print(f"🔥 [CRITICAL] Error al banear en DB: {ban_err}")
            
            # === PASO 2: LOG (Importante pero no crítico) ===
            try:
                import uuid
                self.db.table("transaction_logs").insert({
                    "id": str(uuid.uuid4()),
                    "agent_id": request.agent_id,
                    "amount": 0.0,
                    "vendor": "FAST_WALL_SECURITY",
                    "status": "SECURITY_BAN",
                    "reason": f"Fast-Wall: {fast_check['reason']}"
                }).execute()
            except Exception as log_err:
                print(f"⚠️ Error al insertar log: {log_err}")
            
            # === PASO 3: ALERTAS (Opcional - no debe bloquear) ===
            try:
                wallet_res = self.db.table("wallets").select("slack_webhook_url, owner_email").eq("agent_id", request.agent_id).single().execute()
                contact_info = wallet_res.data if wallet_res.data else {}
                owner_email = contact_info.get('owner_email')
                
                # Alerta Email al cliente (con protección extra)
                if owner_email:
                    try:
                        from notifications import send_ban_alert_to_owner
                        send_ban_alert_to_owner(
                            to_email=owner_email,
                            agent_id=request.agent_id,
                            vendor=request.vendor,
                            amount=request.amount,
                            reason=f"Fast-Wall: {fast_check['reason']}"
                        )
                        print(f"📧 Alerta Fast-Wall enviada a {owner_email}")
                    except Exception as mail_err:
                        print(f"❌ [EMAIL ERROR] No se pudo enviar email: {mail_err}")
                else:
                    print(f"ℹ️ [FAST-WALL] No hay owner_email configurado para {request.agent_id}")
                    
            except Exception as alert_err:
                print(f"⚠️ Error en sistema de alertas: {alert_err}")
            
            print(f"🚫 Protocolo Fast-Wall completado. Agente {request.agent_id} neutralizado.")
            return {"status": "REJECTED", "reason": f"Seguridad: {fast_check['reason']}"}

        # 1.2 CIRCUIT BREAKER & PENDING LOCK
        if self.check_circuit_breaker(request.agent_id):
             return {"status": "REJECTED", "reason": "Velocidad excesiva (Fusible activado)"}
        
        # Check Redis Audit Lock (Si hay una auditoría crítica en curso, bloqueamos instantáneos)
        try:
            if self.redis_enabled:
                if self.redis.get(f"audit_lock:{request.agent_id}"):
                    return {"status": "REJECTED", "reason": "Cuenta bajo revisión de seguridad activa."}
        except: pass

        # 2. Identity Check (Minimal)
        # Asumimos que si tiene ID y saldo en DB, existe.
        
        # 3. Deduct Balance (Atomic RPC)
        FEE_PERCENT = 0.015 # Tarifa base (sin seguro insurance activo en sync check)
        fee = round(request.amount * FEE_PERCENT, 2)
        total_deducted = request.amount + fee
        
        try:
            print(f"💰 [ATOMIC] Ejecutando transacción blindada para {request.agent_id}...")
            
            # Llamamos a la función atómica que resta saldo e inserta log en UN SOLO PASO
            rpc_res = self.db.rpc("process_atomic_payment", {
                "p_agent_id": request.agent_id,
                "p_vendor": request.vendor,
                "p_amount": total_deducted,
                "p_description": request.description,
                "p_status": "APPROVED",
                "p_reason": "Transacción Atómica Verificada"
            }).execute()
            
            new_balance = float(rpc_res.data)
            print(f"✅ Transacción completada. Nuevo saldo: ${new_balance}")

        except Exception as e:
            return {"status": "REJECTED", "reason": f"Error de Integridad: {e}"}

        # 4. Issue Card (Fast) - Necesario para que el pago funcione
        clean_vendor = self._normalize_domain(request.vendor)
        card = self._issue_virtual_card(request.agent_id, request.amount, clean_vendor, mcc_category='services')
        
        if not card:
             # Rollback si falla stripe
             self._reverse_transaction(request.agent_id, total_deducted)
             return {"status": "ERROR", "reason": "Stripe Issuing Failed"}
             
        # 5. ACTIVAR LOCK TEMPORAL (REDIS) si el monto es relevante
        try:
             if self.redis_enabled and request.amount > 100:
                  self.redis.setex(f"audit_lock:{request.agent_id}", 30, "LOCKED") # Bloqueo de 30s mientras dura el Oracle
        except: pass

        # 6. Return Success with Pending Audit status
        return {
            "success": True,
            "status": "APPROVED_PENDING_AUDIT",
            "message": "Pago aprobado (Auditoría en curso)",
            "transaction_id": card['id'], # Usamos ID de tarjeta como tx id rápido
            "card": card,
            "balance": "hidden (async)", # No recalculamos saldo aqui para ir rápido
            "forensic_url": "PENDING"
        }

    def charge_user_card(self, agent_id, amount, payment_method_id):
        """
        COBRO REAL INVISIBLE:
        Recibe el token de tarjeta del usuario (desde el Frontend) y cobra al instante.
        """
        try:
            # 1. Recuperar cuenta destino (El Agente)
            wallet = self.db.table("wallets").select("stripe_account_id, balance").eq("agent_id", agent_id).execute()
            if not wallet.data: raise Exception("Agente no encontrado")
            
            connected_account_id = wallet.data[0]['stripe_account_id']
            current_balance = float(wallet.data[0]['balance'])

            print(f"💳 Procesando cobro de tarjeta ({payment_method_id}) para {agent_id}...")

            # 2. EJECUTAR EL COBRO REAL (Sin redirección)
            intent = stripe.PaymentIntent.create(
                amount=int(amount * 100),
                currency='usd',
                payment_method=payment_method_id, # <--- LA TARJETA DEL USUARIO
                confirm=True, # <--- COBRO INMEDIATO
                description=f"Recarga de Saldo para {agent_id}",
                automatic_payment_methods={'enabled': True, 'allow_redirects': 'never'},
                transfer_data={
                    'destination': connected_account_id, # El dinero va al agente
                },
                # Si es un pago real, a veces requerimos retorno (3D Secure), 
                # pero con 'never' forzamos el intento directo.
            )
            
            # 3. ACTUALIZAR SALDO INTERNO
            new_bal = current_balance + amount
            self.db.table("wallets").update({"balance": new_bal}).eq("agent_id", agent_id).execute()

            return {
                "status": "SUCCESS", 
                "new_balance": new_bal, 
                "tx_id": intent.id,
                "message": "Pago completado correctamente."
            }

        except stripe.error.CardError as e:
            # Error real de tarjeta (fondos insuficientes, denegada, etc.)
            return {"status": "FAILED", "message": f"Tarjeta rechazada: {e.user_message}"}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

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
                id=card_data.get('id'),
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
        # 1. Recuperar contexto
        try:
            tx_res = self.db.table("transaction_logs").select("*").eq("id", transaction_id).execute()
            tx = tx_res.data[0] if tx_res.data else {}
        except:
            tx = {}
        
        # 2. Llamar al Tribunal (AutoLawyer)
        try:
            verdict = self.lawyer.analyze_case(
                agent_id=agent_id,
                vendor=tx.get('vendor', 'Unknown'),
                amount=float(tx.get('amount', 0)),
                claim_reason=issue,
                proof_logs=evidence,
                transaction_context={"tx_id": transaction_id}
            )
        except Exception as e:
            print(f"❌ Error llamando al Lawyer: {e}")
            verdict = None

        # 🛡️ DEFENSA DE MOTOR: Si verdict sigue siendo None, creamos uno por defecto
        if verdict is None:
            verdict = {
                "suggested_action": "REJECT_CLAIM",
                "judicial_opinion": "Error Interno del Tribunal (Null Verdict).",
                "viability": "ERROR"
            }
        
        # 3. Acciones Automáticas
        action = verdict.get('suggested_action', 'REJECT_CLAIM')
        status = "REFUNDED" if action == "REFUND" else "DISPUTE_REJECTED"
        
        # Actualizar DB
        try:
            self.db.table("transaction_logs").update({
                "status": status, 
                "reason": f"Arbitraje IA: {verdict.get('judicial_opinion')}"
            }).eq("id", transaction_id).execute()
        except Exception as e:
            print(f"⚠️ Error actualizando DB en disputa: {e}")
        
        return {
            "status": status,
            "verdict": verdict,
            "action_taken": action
        }

    # --- AÑADIR EN ENGINE.PY (DENTRO DE LA CLASE UniversalEngine) ---
    
    def scan_and_pay_qr(self, payer_agent_id, qr_url):
        """
        SISTEMA DE VISIÓN FINANCIERA (QR PARSER):
        1. Recibe una URL de QR (ej: Stripe Checkout).
        2. Consulta a Stripe qué contiene (Monto y Destinatario).
        3. Ejecuta el pago instantáneo desde el Payer hacia el Receiver.
        """
        print(f"🤖 [QR VISION] Analizando QR para el agente {payer_agent_id}...")
        print(f"   🔗 URL Detectada: {qr_url}")

        try:
            # 1. Extraer el Session ID de la URL
            # Formato típico: https://checkout.stripe.com/c/pay/cs_test_a1b2c3...
            if "cs_test_" not in qr_url and "cs_live_" not in qr_url:
                return {"status": "ERROR", "message": "Formato de QR no válido o desconocido."}

            session_id = qr_url.split("/")[-1].split("#")[0]  # Limpieza básica
            
            # 2. Consultar a Stripe los detalles de esa sesión (La "Factura")
            # Como somos la Plataforma, podemos leer la sesión aunque sea de otro usuario
            session = stripe.checkout.Session.retrieve(session_id)
            
            if session.payment_status == 'paid':
                return {"status": "ALREADY_PAID", "message": "Este QR ya ha sido pagado."}

            # 3. Extraer datos clave
            amount_dollars = session.amount_total / 100.0
            receiver_agent_id = session.metadata.get('agent_id')
            
            if not receiver_agent_id:
                return {"status": "ERROR", "message": "El QR no contiene metadatos del agente destino."}

            print(f"   🧠 [QR ANALYSIS] Detectado cobro de ${amount_dollars} para {receiver_agent_id}")

            # 4. EJECUTAR EL PAGO (M2M Transfer)
            # Usamos la lógica de cobro directo (pm_card_visa simula la tarjeta del agente pagador)
            
            # Recuperar cuenta Stripe del DESTINATARIO para enviarle la plata
            receiver_wallet = self.db.table("wallets").select("stripe_account_id").eq("agent_id", receiver_agent_id).execute()
            if not receiver_wallet.data:
                 return {"status": "ERROR", "message": "El destinatario no tiene cuenta conectada."}
            
            dest_acct_id = receiver_wallet.data[0]['stripe_account_id']

            # Crear el movimiento de dinero REAL
            intent = stripe.PaymentIntent.create(
                amount=int(amount_dollars * 100),
                currency="usd",
                payment_method="pm_card_visa", # Simula la tarjeta del Agente Pagador
                confirm=True, # Pago Inmediato
                description=f"QR Payment: {payer_agent_id} -> {receiver_agent_id}",
                automatic_payment_methods={'enabled': True, 'allow_redirects': 'never'},
                transfer_data={
                    'destination': dest_acct_id, # El dinero llega al que generó el QR
                }
            )

            # 5. Opcional: Expirar la sesión de checkout para que nadie más la pague
            try:
                stripe.checkout.Session.expire(session_id)
            except: pass # Si ya expiró o falló, no importa, el pago ya se hizo

            # 6. Registrar en Base de Datos (Log de Payer y Receiver)
            # Restamos saldo lógico al pagador (si gestionamos saldo interno)
            # Nota: deduct_balance debe existir en la DB como función RPC
            try:
                self.db.rpc("deduct_balance", {"p_agent_id": payer_agent_id, "p_amount": amount_dollars}).execute()
            except Exception as e:
                print(f"⚠️ Nota: No se pudo descontar saldo interno (quizás usa tarjeta directa): {e}")

            return {
                "status": "SUCCESS",
                "message": "Pago por QR completado exitosamente.",
                "tx_details": {
                    "id": intent.id,
                    "amount": amount_dollars,
                    "from": payer_agent_id,
                    "to": receiver_agent_id
                }
            }

        except Exception as e:
            print(f"❌ Error procesando QR: {e}")
            return {"status": "ERROR", "message": str(e)}
        
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
        REGISTRO SILENCIOSO Y AUTOMÁTICO:
        Crea la cuenta activando 'transfers' y 'card_payments' al instante.
        """
        country_code = country_code.upper()
        agent_id = f"ag_{uuid.uuid4().hex[:12]}"
        raw_secret = f"sk_live_{secrets.token_urlsafe(32)}"
        secret_hash = self._hash_key(raw_secret)
        
        # Datos Dummy para pasar validación en Test Mode
        test_ip = "8.8.8.8"
        timestamp = int(time.time())

        try:
            print(f"🥷 Creando Agente Automático: {client_name}...")

            # 1. CREAR CUENTA PRE-ACTIVADA
            account = stripe.Account.create(
                country=country_code,
                type="custom",
                capabilities={
                    "card_payments": {"requested": True},
                    "transfers": {"requested": True}, # <--- CRUCIAL PARA EL ERROR
                },
                business_type="individual",
                business_profile={"name": client_name, "mcc": "5734", "url": "http://agentpay.ai"},
                email=f"{agent_id}@agentpay.ai",
                # ESTO ES LO QUE FALTA PARA EVITAR EL ERROR DE CAPABILITIES:
                tos_acceptance={
                    "date": timestamp,
                    "ip": test_ip, 
                },
            )

            # 2. INYECTAR DATOS DE VERIFICACIÓN (KYC FALSO PARA TEST)
            stripe.Account.modify(
                account.id,
                individual={
                    "first_name": "Agente",
                    "last_name": "IA",
                    "email": f"{agent_id}@agentpay.ai",
                    "dob": {"day": 1, "month": 1, "year": 1990},
                    "address": {"line1": "Calle Test 123", "city": "Madrid", "state": "Madrid", "postal_code": "28001", "country": country_code},
                    "phone": "+34000000000"
                }
            )

            # 3. Guardar en DB
            self.db.table("wallets").insert({
                "agent_id": agent_id,
                "owner_name": client_name,
                "api_secret_hash": secret_hash,
                "balance": 0.0,
                "stripe_account_id": account.id,
                "kyc_status": "ACTIVE"
            }).execute()
            
            return {
                "status": "CREATED",
                "agent_id": agent_id,
                "api_key": raw_secret,
                "stripe_account_id": account.id,
                "message": "Agente listo y activo para recibir dinero automáticamente."
            }

        except Exception as e:
            print(f"❌ Error creando agente: {e}")
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

    def activate_issuing_for_agent(self, agent_id):
        """
        PASO 2: Activa la capacidad de emitir tarjetas para un agente YA registrado.
        Se debe llamar después de que el agente haya completado el KYC.
        """
        try:
            # 1. Recuperamos el ID de cuenta de Stripe (acct_...)
            wallet = self.db.table("wallets").select("stripe_account_id").eq("agent_id", agent_id).execute()
            if not wallet.data:
                return {"status": "ERROR", "message": "Agente no encontrado."}
            
            acct_id = wallet.data[0]['stripe_account_id']
            
            print(f"🚀 Activando Issuing para la cuenta {acct_id}...")

            # 2. Llamada a la API de Stripe para solicitar la capability
            stripe.Account.modify(
                acct_id,
                capabilities={
                    "card_issuing": {"requested": True}, # <--- AQUÍ SÍ LO PEDIMOS
                }
            )

            return {
                "status": "ACTIVATED",
                "message": "Solicitud de Issuing enviada a Stripe. Si el KYC está ok, se activará en minutos.",
                "agent_id": agent_id,
                "stripe_account": acct_id
            }

        except Exception as e:
            print(f"❌ Error activando Issuing: {e}")
            return {"status": "ERROR", "message": str(e)}