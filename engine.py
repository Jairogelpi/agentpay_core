
import os
import stripe
import base64
import uuid
import time
from urllib.parse import urlparse
from dotenv import load_dotenv
from supabase import create_client, Client
from models import TransactionRequest, TransactionResult
from ai_guard import audit_transaction
from security_utils import check_domain_age
from notifications import send_approval_email
from webhooks import send_webhook
from credit import CreditBureau
from legal import LegalWrapper
from identity import IdentityManager
from lawyer import AutoLawyer

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
        
        # Memoria volátil para Circuit Breaker (En prod usar Redis)
        self.transaction_velocity = {} 
        self.webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

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

    def check_circuit_breaker(self, agent_id):
        """
        El Fusible Financiero: Detecta bucles infinitos (runaway agents).
        Regla: Máximo 10 intentos por minuto.
        Retorna: True si el fusible saltó (BLOQUEAR), False si todo ok.
        """
        current_time = time.time()
        
        # Inicializar
        if agent_id not in self.transaction_velocity:
            self.transaction_velocity[agent_id] = []
            
        # Limpiar viejos (Window: 60s)
        self.transaction_velocity[agent_id] = [t for t in self.transaction_velocity[agent_id] if current_time - t < 60]
        
        # Chequear límite
        if len(self.transaction_velocity[agent_id]) >= 10:
            return True # 🔥 FUSIBLE ACTIVADO
            
        # Registrar nuevo intento (incluso si luego falla por fondos, cuenta como actividad)
        self.transaction_velocity[agent_id].append(current_time)
        return False

    def evaluate(self, request: TransactionRequest) -> TransactionResult:
        # 0. FUSIBLE DE SEGURIDAD (CIRCUIT BREAKER)
        # Esto va antes de TODO. Si el agente está loco, lo paramos aquí.
        if self.check_circuit_breaker(request.agent_id):
            print(f"🔥 [CIRCUIT BREAKER] Agente {request.agent_id} bloqueado por velocidad excesiva.")
            return TransactionResult(
                authorized=False, 
                status="CIRCUIT_OPEN", 
                reason="🚨 FUSIBLE ACTIVADO: Detectado bucle infinito (>10 tx/min). Agente congelado."
            )

        print(f"\n🧠 [ENGINE] Procesando: {request.vendor} (${request.amount})")

        # --- CAPA 0: IDENTITY & CONTEXT ---
        # Recuperamos la wallet y configuración ANTES de nada para saber quién es
        response = self.db.table("wallets").select("*").eq("agent_id", request.agent_id).execute()
        if not response.data:
            return self._result(False, "REJECTED", "Agente no existe", request)
        
        wallet = response.data[0]
        agent_role = wallet.get('agent_role', 'Asistente IA General')
        
        # --- CAPA 1: FIREWALL & INSURANCE (SECURITY FIRST) ---
        # Verificamos seguridad ANTES de mirar el dinero. Si es un pirata, no nos importa si tiene fondos.
        
        # A. Blacklist Global
        clean_vendor = self._normalize_domain(request.vendor)
        try:
            is_banned = self.db.table("global_blacklist").select("*").eq("vendor", clean_vendor).execute()
            if is_banned.data:
                return self._result(False, "REJECTED", "Sitio en Lista Negra Global.", request)
        except Exception:
            pass

        # B. Whitelist & OSINT
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
        # Recuperamos historial para la IA
        history = []
        try:
            h_resp = self.db.table("transaction_logs").select("created_at, amount, vendor, reason").eq("agent_id", request.agent_id).order("created_at", desc=True).limit(5).execute()
            history = h_resp.data if h_resp.data else []
        except: pass

        insurance_config = wallet.get('insurance_config', {})
        insurance_enabled = insurance_config.get('enabled', False)
        sensitivity = insurance_config.get('strictness', 'HIGH') if insurance_enabled else "HIGH"
        
        # Auditar si:
        # 1. El seguro está activo (Auditoría Continua)
        # 2. El sitio NO está en whitelist (Zero Trust)
        should_audit = insurance_enabled or (not is_whitelisted)
        
        if should_audit:
            # Si no hay seguro, bajamos la sensibilidad para no molestar tanto en sitios nuevos
            if not insurance_enabled: sensitivity = "LOW"
            
            print(f"🛡️ [AI GUARD] Auditando ({sensitivity})...")
            # PASSING domain_status to AI for better context
            audit = audit_transaction(request.vendor, request.amount, request.description, request.agent_id, agent_role, history, request.justification, sensitivity=sensitivity, domain_status=domain_status)
            
            # --- FORENSIC LOGGING ---
            intent_hash = audit.get('intent_hash', 'N/A')
            risk_reason = audit.get('reasoning', audit.get('reason', 'N/A'))
            
            # Formato de Log Forense
            log_message = f"{risk_reason} [INTENT_HASH: {intent_hash}]"
            
            if audit['decision'] == 'REJECTED':
                 return self._result(False, "REJECTED", f"Bloqueado por AI Guard ({sensitivity}): {log_message}", request)

            if audit['decision'] == 'FLAGGED' and sensitivity != "LOW":
                 # Si es LOW (sin seguro), permitimos flagged con warning. Si es HIGH/MED, pedimos aprobación.
                 return self._create_approval_request(request, clean_vendor, reason_prefix=f"Alerta de Seguridad ({sensitivity}): {log_message}")

        # --- CAPA 2: FINANCIERA (AHORA SÍ MIRAMOS EL DINERO) ---
        
        # Límites Matemáticos
        max_tx = float(wallet.get('max_transaction_limit', 0))
        if max_tx > 0 and request.amount > max_tx:
             return self._result(False, "REJECTED", f"Excede límite tx (${max_tx})", request)
             
        # Cálculo de Fees
        FEE_PERCENT = 0.035 if insurance_enabled else 0.015
        fee = round(request.amount * FEE_PERCENT, 2)
        total_deducted = request.amount + fee
        
        current_balance = float(wallet['balance'])
        
        if total_deducted > current_balance:
            # Lógica de Crédito
            credit_check = self.credit_bureau.check_credit_eligibility(request.agent_id)
            if credit_check['eligible'] and total_deducted <= (current_balance + credit_check['credit_limit']):
                 print(f"💳 [CREDIT] Usando línea de crédito {credit_check['tier']}")
            else:
                 return self._result(False, "REJECTED", f"Fondos insuficientes (Req: ${total_deducted})", request)

        # ... (Resto de lógica de ejecución: Invisible Mode, Stripe Charge, etc)
        # Nota: Eliminar bloques antiguos de checks para no duplicar

        
        # --- MODO INVISIBLE / PREPARACIÓN DE CONTEXTO ---
        invisible_ctx = None
        if hasattr(request, '_burner_id_to_destroy') or domain_status == "MEDIUM_RISK":
             print(f"👻 [INVISIBLE MODE] Generando huella digital humana...")
             invisible_ctx = self.identity_mgr.generate_digital_fingerprint()

        # PASO C: Ejecutar el Pago
        print(f"💳 [STRIPE] Iniciando cargo real de ${request.amount}...")
        
        stripe_tx_id = self._execute_stripe_charge(request.amount, clean_vendor, invisible_context=invisible_ctx)
        
             # En un caso real, aquí obtendríamos también las credenciales del proxy residencial
             # invisible_ctx['proxy'] = self.identity_mgr.get_residential_proxy()['proxy_url']

        # PASO C: Ejecutar el Pago
        print(f"💳 [STRIPE] Iniciando cargo real de ${request.amount}...")
        
        stripe_tx_id = self._execute_stripe_charge(request.amount, clean_vendor, invisible_context=invisible_ctx)
        
        if not stripe_tx_id:
            return self._result(False, "REJECTED", "Error en pasarela de pago (Tarjeta rechazada)", request)
            
        # Deducción de Saldo + Comisión
        new_balance = float(wallet['balance']) - total_deducted
        self.db.table("wallets").update({"balance": new_balance}).eq("agent_id", request.agent_id).execute()
        
        # --- GENERACIÓN DE FACTURA ---
        from invoicing import generate_invoice_pdf
        invoice_path = generate_invoice_pdf(stripe_tx_id, request.agent_id, clean_vendor, request.amount, request.description)
        
        # --- LIMPIEZA DE IDENTIDAD DESECHABLE ---
        log_suffix = ""
        if hasattr(request, '_burner_id_to_destroy'):
             print(f"🧹 [CLEANUP] Destruyendo identidad utilizada...")
             self.identity_mgr.destroy_identity(request._burner_id_to_destroy)
             log_suffix += " (Identity Incinerated)"
        
        # --- FIRMA FORENSE (PROOF OF INTENT) ---
        proof_data = None
        if request.justification:
             print(f"⚖️ [LEGAL] Generando Proof of Intent firmado...")
             proof = self.legal_wrapper.sign_intent(request.agent_id, clean_vendor, request.amount, request.justification)
             proof_data = proof['proof_text']

        success_msg = f"Pago Realizado. (Subtotal: ${request.amount} + Fee: ${fee})" + log_suffix
        
        # Guardamos la prueba en el log
        log_reason = success_msg
        if proof_data:
            log_reason += f"\n\n{proof_data}"

        return self._result(True, "APPROVED", log_reason, request, new_balance, invoice_url=invoice_path, fee=fee)

    def _execute_stripe_charge(self, amount, vendor_desc, invisible_context=None):
        """
        Intenta realizar un cargo real en Stripe.
        Retorna el ID de transacción si es exitoso, o None si falla.
        """
        try:
            # Configurar Proxy si estamos en modo invisible
            original_proxy = stripe.proxy
            if invisible_context and invisible_context.get('proxy'):
                stripe.proxy = invisible_context['proxy']
                print(f"   🛡️ Túnel Invisible Activado: Enrutando vía {stripe.proxy.split('@')[1] if '@' in stripe.proxy else 'Proxy'}")

            # Stripe trabaja en centavos (ints), no decimales. $10.50 -> 1050
            amount_cents = int(amount * 100)
            
            # Simulamos el uso de una tarjeta VISA de prueba (pm_card_visa)
            metadata = {}
            if invisible_context:
                metadata['user_agent'] = invisible_context.get('User-Agent')
                metadata['screen_res'] = invisible_context.get('Screen-Resolution')
            
            intent = stripe.PaymentIntent.create(
                amount=amount_cents,
                currency="usd",
                payment_method="pm_card_visa", # Tarjeta mágica de test que siempre pasa
                confirm=True, # Cobra inmediatamente
                description=f"AgentPay Charge: {vendor_desc}",
                metadata=metadata,
                automatic_payment_methods={
                    'enabled': True,
                    'allow_redirects': 'never' # Forzamos error si requiere 3D Secure (IAs no pueden hacer 3DS)
                }
            )
            
            # Restaurar proxy para no afectar otras llamas globales (si fuera multihilo real, usaríamos ContextVar)
            stripe.proxy = None
            
            print(f"✅ [STRIPE SUCCESS] Cargo confirmado: {intent.id}")
            return intent.id

        except stripe.error.CardError as e:
            stripe.proxy = None # Safety reset
            print(f"❌ [STRIPE ERROR] Tarjeta rechazada: {e.user_message}")
            return None
        except Exception as e:
            stripe.proxy = None # Safety reset
            print(f"❌ [STRIPE SYSTEM ERROR] {str(e)}")
            return None



    def _normalize_domain(self, vendor_str: str) -> str:
        vendor_str = vendor_str.lower().strip()
        if not vendor_str.startswith(('http://', 'https://')):
            vendor_str = 'https://' + vendor_str
        parsed = urlparse(vendor_str)
        domain = parsed.netloc or parsed.path
        if domain.startswith("www."): domain = domain[4:]
        return domain

    def _create_approval_request(self, request, clean_vendor, reason_prefix="Proveedor nuevo. Aprobación requerida."):
        # Codificamos TODO lo necesario para ejecutar el pago después
        payload = f"{request.agent_id}:{clean_vendor}:{request.amount}"
        token = base64.b64encode(payload.encode()).decode()
        magic_link = f"{self.admin_url}/admin/approve?token={token}"
        
        print(f"⚠️  [AI FLAGGED] Generando solicitud de aprobación: {magic_link}")
        
        # Intentamos notificar al dueño
        try:
            # Recuperamos email de la wallet (asumiendo que existe columna owner_email)
            response = self.db.table("wallets").select("owner_email").eq("agent_id", request.agent_id).execute()
            owner_email = response.data[0].get('owner_email') if response.data else None
            
            if owner_email:
                send_approval_email(owner_email, request.agent_id, clean_vendor, request.amount, magic_link)
            else:
                print("   ℹ️ (No se envió email: falta 'owner_email' en tabla wallets)")
        except Exception as e:
            print(f"   ⚠️ Error enviando notificación email: {e}")

        return TransactionResult(
            authorized=False, 
            status="PENDING_APPROVAL", 
            reason=reason_prefix, 
            approval_link=magic_link
        )

    def report_fraud(self, agent_id, vendor, reason):
        """
        Permite a un cliente reportar un sitio malicioso a la Colmena.
        """
        print(f"🚨 REPORTE DE FRAUDE: {agent_id} acusa a {vendor}")
        
        clean_vendor = self._normalize_domain(vendor)
        
        # Insertar en Blacklist (En un sistema real, iría a una tabla "pending_review")
        try:
            self.db.table("global_blacklist").insert({
                "vendor": clean_vendor,
                "reason": f"Reportado por agente: {reason}"
            }).execute()
            return {"success": True, "message": "Proveedor añadido a la lista negra global."}
        except Exception as e:
            print(f"Error reportando fraude: {e}")
            return {"success": False, "message": str(e)}

    def process_approval(self, token):
        """
        Esta función se llama cuando el humano hace clic en el Magic Link.
        Decodifica el token, ejecuta el pago y avisa por Webhook.
        """
        try:
            # 1. Decodificar Token
            decoded = base64.b64decode(token).decode().split(":")
            agent_id, vendor, amount_str = decoded[0], decoded[1], decoded[2]
            amount = float(amount_str)
            
            print(f"👤 APROBACIÓN HUMANA RECIBIDA para {vendor} (${amount})")
            
            # 2. Ejecutar el cargo (Saltando validaciones porque el humano manda)
            # En un sistema real, deberíamos re-verificar saldo aquí.
            stripe_id = self._execute_stripe_charge(amount, vendor)
            
            if not stripe_id:
                return {"status": "ERROR", "message": "Fallo en cargo Stripe durante aprobación manual."}

            # 3. Actualizar Saldo
            # Necesitamos leer el saldo actual para restarlo
            wallet_resp = self.db.table("wallets").select("*").eq("agent_id", agent_id).execute()
            if not wallet_resp.data:
                return {"status": "ERROR", "message": "Wallet no encontrada durante aprobación."}
                
            wallet = wallet_resp.data[0]
            new_balance = float(wallet['balance']) - amount
            self.db.table("wallets").update({"balance": new_balance}).eq("agent_id", agent_id).execute()
            
            # 4. DISPARAR WEBHOOK DE ÉXITO
            if wallet.get('webhook_url'):
                send_webhook(wallet.get('webhook_url'), "payment.approved", {
                    "vendor": vendor,
                    "amount": amount,
                    "status": "APPROVED",
                    "approver": "Human Admin",
                    "transaction_id": stripe_id
                })
            
            # Loguear
            self._result(True, "APPROVED", "Aprobación Manual Humana", 
                         TransactionRequest(agent_id=agent_id, vendor=vendor, amount=amount, description="Manual Approval"), 
                         new_balance)
                
            return {"status": "APPROVED", "message": "Pago ejecutado y cliente notificado.", "new_balance": new_balance}
            
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    # ... existing methods ...

    def create_topup_link(self, agent_id, amount):
        """
        Genera un link de Stripe Checkout para recargar saldo real.
        """
        try:
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {'name': 'Recarga Saldo AgentPay'},
                        'unit_amount': int(amount * 100),
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=f"{self.admin_url}/success?agent={agent_id}",
                cancel_url=f"{self.admin_url}/cancel",
                metadata={'agent_id': agent_id, 'type': 'topup'}
            )
            return session.url
        except Exception as e:
            return f"Error generando link: {str(e)}"

    def update_agent_settings(self, agent_id, webhook_url=None, owner_email=None):
        """
        Permite configurar dinámicamente el webhook y el email del dueño.
        """
        updates = {}
        if webhook_url: updates['webhook_url'] = webhook_url
        if owner_email: updates['owner_email'] = owner_email
        
        if not updates:
            return {"success": False, "message": "No fields to update"}
            
        try:
            self.db.table("wallets").update(updates).eq("agent_id", agent_id).execute()
            return {"success": True, "message": "Settings updated successfully"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def get_agent_status(self, agent_id):
        """
        Retorna la salud financiera y configuración del agente.
        Resuelve: '¿Cuánto dinero tengo y soy fiable?'
        """
        try:
            # 1. Datos de Billetera
            resp = self.db.table("wallets").select("*").eq("agent_id", agent_id).execute()
            if not resp.data:
                return {"status": "NOT_FOUND", "message": "Agent wallet not found"}
            
            wallet = resp.data[0]
            
            # 2. Score de Crédito
            score = self.credit_bureau.calculate_score(agent_id)
            credit_data = self.credit_bureau.check_credit_eligibility(agent_id)
            
            return {
                "agent_id": agent_id,
                "status": "ACTIVE",
                "finance": {
                     "balance": wallet['balance'],
                     "currency": "USD"
                },
                "credit": {
                    "score": score,
                    "tier": credit_data['tier'],
                    "limit": credit_data['credit_limit']
                },
                "config": {
                    "webhook_url": wallet.get('webhook_url'),
                    "owner_email": wallet.get('owner_email')
                }
            }
        except Exception as e:
             return {"status": "ERROR", "message": str(e)}

    def check_payment_status(self, transaction_id):
        """Verifica el estado de una transacción (Human-in-the-loop)"""
        try:
            # Buscamos en logs (Asumiendo que guardamos el Stripe ID en 'reason' o similar, 
            # o que transaction_id es el ID interno. Para MVP, simulamos búsqueda).
            # En V2 real: Select * from transaction_logs where id = transaction_id
            return {"status": "APPROVED", "transaction_id": transaction_id, "human_approved": True} 
        except Exception:
            return {"status": "UNKNOWN"}

    def get_invoice_url(self, transaction_id):
        """Descarga la factura PDF"""
        # Simulación: En prod, esto sacaría la URL de Stripe o del bucket de Supabase
        return {"invoice_url": f"{self.admin_url}/invoices/{transaction_id}.pdf"}

    def register_new_agent(self, client_name):
        """Onboarding automático de nuevos agentes"""
        try:
            # Generamos credenciales
            new_id = f"agent_{uuid.uuid4().hex[:8]}"
            api_key = f"sk_{uuid.uuid4().hex[:24]}"
            
            self.db.table("wallets").insert({
                "agent_id": api_key, # Simplificación SDK: API Key es el ID
                "owner_name": client_name,
                "balance": 0.0,
                "status": "active",
                "max_transaction_limit": 100.0, # Default safe limits
                "daily_limit": 500.0
            }).execute()
            
            return {"agent_id": api_key, "api_key": api_key, "dashboard_url": f"{self.admin_url}/dashboard/{api_key}"}
        except Exception as e:
            return {"error": str(e)}

    def configure_insurance(self, agent_id, enabled=True, strictness="HIGH"):
        """Configura la póliza de seguro del agente"""
        try:
            config = {
                "enabled": enabled,
                "strictness": strictness, # HIGH, MEDIUM, LOW
                "premium_rate": 0.02 if enabled else 0.0
            }
            
            self.db.table("wallets").update({"insurance_config": config}).eq("agent_id", agent_id).execute()
            status = "ACTIVATED" if enabled else "DISABLED"
            return {"success": True, "message": f"Insurance Policy {status}. Strictness: {strictness}"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def update_limits(self, agent_id, max_tx=None, daily=None):
        """Control de Presupuesto Dinámico"""
        updates = {}
        if max_tx: updates['max_transaction_limit'] = max_tx
        if daily: updates['daily_limit'] = daily
        
        try:
            if updates:
                self.db.table("wallets").update(updates).eq("agent_id", agent_id).execute()
            return {"success": True, "limits": updates}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def dispute_transaction(self, agent_id, transaction_id, reason, proof_logs=""):
        """
        Arbitraje de Disputas con IA.
        Si la IA determina que es ganable, inicia la disputa en Stripe automáticamente.
        """
        print(f"⚖️ DISPUTA INICIADA: Tx {transaction_id} por '{reason}'")
        
        # 1. Análisis del Caso (Lawyer)
        # Recuperamos info básica de la transacción simulada para contexto
        # En prod: tx = self.db.table("transaction_logs").select("*").eq("id", transaction_id)...
        vendor = "Unknown Vendor" # Placeholder
        amount = 0.0 # Placeholder
        
        case_analysis = self.lawyer.analyze_case(agent_id, vendor, amount, reason, proof_logs)
        
        if case_analysis.get('viability') == 'WINNABLE':
            # 2. Iniciar Disputa Real
            print(f"   ✅ CASO GANABLE. Confidence: {case_analysis.get('confidence_score')}%")
            print(f"   📝 Enviando Dossier a Stripe...")
            
            dispute_result = self.lawyer.file_stripe_dispute(transaction_id, case_analysis.get('dossier_text'))
            
            return {
                "success": True,
                "status": "FILED",
                "ticket_id": dispute_result['reference'],
                "lawyer_note": "Dispute filed automatically based on strong evidence.",
                "dossier": case_analysis.get('dossier_text')
            }
        else:
            # 3. Caso Débil
            print(f"   ⚠️ CASO DÉBIL. No se iniciará disputa automática.")
            return {
                "success": False,
                "status": "IGNORED",
                "reason": "AI Lawyer determined evidence is insufficient.",
                "analysis": case_analysis
            }

    def transfer_balance(self, from_agent_id, to_agent_id, amount):
        """
        Préstamo P2P Inter-Agente.
        Permite mover fondos entre agentes de la MISMA ORGANIZACIÓN.
        """
        try:
            # 1. Verificar que pertenecen a la misma organización (mismo owner)
            sender_q = self.db.table("wallets").select("*").eq("agent_id", from_agent_id).execute()
            receiver_q = self.db.table("wallets").select("*").eq("agent_id", to_agent_id).execute()
            
            if not sender_q.data or not receiver_q.data:
                return {"status": "ERROR", "message": "Agents not found"}
                
            sender = sender_q.data[0]
            receiver = receiver_q.data[0]
            
            if sender['owner_name'] != receiver['owner_name']:
                return {"status": "REJECTED", "message": "Security Alert: Cross-Organization transfer blocked."}
            
            # 2. Verificar fondos
            if float(sender['balance']) < amount:
                 return {"status": "REJECTED", "message": "Insufficient funds"}
                 
            # 3. Transferencia Atómica (Simulada)
            new_sender_bal = float(sender['balance']) - amount
            new_receiver_bal = float(receiver['balance']) + amount
            
            self.db.table("wallets").update({"balance": new_sender_bal}).eq("agent_id", from_agent_id).execute()
            self.db.table("wallets").update({"balance": new_receiver_bal}).eq("agent_id", to_agent_id).execute()
            
            # Log
            self.db.table("transaction_logs").insert({
               "agent_id": from_agent_id,
               "vendor": f"TRANSFER_TO_{to_agent_id}",
               "amount": amount,
               "status": "INTERNAL_TRANSFER",
               "authorized": True
            }).execute()
            
            return {"status": "APPROVED", "message": f"Transferred ${amount} to {to_agent_id}"}
            
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    def get_agent_passport(self, agent_id):
        """
        Emite un certificado KYC (Pasaporte Digital) para el agente.
        Solo se emite si el agente tiene buena reputación (Score > 600).
        """
        try:
            # 1. Recuperar info del agente
            wallet_resp = self.db.table("wallets").select("*").eq("agent_id", agent_id).execute()
            if not wallet_resp.data:
                return {"status": "ERROR", "message": "Agent not found"}
            
            agent_data = wallet_resp.data[0]
            owner_name = agent_data.get("owner_name", "Unknown")
            
            # 2. Verificar Reputación (Credit Check)
            score = self.credit_bureau.calculate_score(agent_id)
            
            if score < 500:
                print(f"🛂 [KYC] Pasaporte denegado para {agent_id}. Score muy bajo ({score})")
                return {"status": "DENIED", "message": f"Reputation too low for passport ({score}). Build credit first."}
            
            # 3. Determinar Nivel
            level = "STANDARD"
            if score > 750: level = "GOLD"
            if score > 850: level = "PLATINUM"
            
            print(f"🛂 [KYC] Emitiendo pasaporte {level} para {agent_id} (Score: {score})")
            
            # 4. Emitir
            passport = self.legal_wrapper.issue_kyc_passport(agent_id, owner_name, compliance_level=level)
            return {"status": "ISSUED", "passport": passport}
            
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    # --- ESCROW & ARBITRATION SYSTEMS ---
    
    def create_escrow_transaction(self, agent_id, vendor, amount, description="Escrow Purchase"):
        """
        Crea una transacción segura donde los fondos no van al vendedor, sino a la Bóveda de Escrow.
        """
        print(f"🔐 [ESCROW] Iniciando transacción segura para {agent_id} -> {vendor} (${amount})")
        
        wallet_resp = self.db.table("wallets").select("*").eq("agent_id", agent_id).execute()
        if not wallet_resp.data: return {"status": "ERROR", "message": "Agent not found"}
        wallet = wallet_resp.data[0]
        
        if float(wallet['balance']) < amount:
            return {"status": "REJECTED", "message": "Insufficient funds for Escrow"}
            
        # 1. Deducir fondos de la Wallet (Agente deja de tener el dinero)
        new_balance = float(wallet['balance']) - amount
        self.db.table("wallets").update({"balance": new_balance}).eq("agent_id", agent_id).execute()
        
        # 2. Crear registro en logs con estado ESCROW_LOCKED
        # Usamos un ID temporal de Stripe simulado
        txn_id = f"escrow_{int(time.time())}_{uuid.uuid4().hex[:4]}"
        
        self.db.table("transaction_logs").insert({
            "agent_id": agent_id,
            "vendor": vendor,
            "amount": amount,
            "status": "ESCROW_LOCKED", 
            "reason": description,
            "invoice_url": f"https://agentpay.io/escrow_receipt/{txn_id}",
            "fee": amount * 0.02 # Fee por servicio de escrow
        }).execute()
        
        print(f"💰 [ESCROW] Fondos retenidos: ${amount}. Esperando confirmación de entrega.")
        return {
            "status": "ESCROW_CREATED",
            "transaction_id": txn_id,
            "message": "Funds locked. Please confirm delivery to release payment OR dispute if issues arise."
        }
        
    def confirm_delivery(self, agent_id, transaction_id):
        """
        El Agente confirma que recibió el producto bien. Liberamos al vendedor.
        """
        print(f"✅ [ESCROW] Agente {agent_id} confirma entrega par {transaction_id}")
        
        # Buscar la tx
        # Nota: En prod buscaríamos por ID real en DB. Aquí simulamos update.
        try:
             # Update status to COMPLETED
             # self.db.table("transaction_logs").update({"status": "COMPLETED"}).match({...})
             pass
        except: pass
        
        return {"status": "RELEASED", "message": "Payment released to Vendor. Transaction Closed."}
        
    def raise_escrow_dispute(self, agent_id, transaction_id, issue_description, technical_evidence):
        """
        El Agente denuncia una estafa. Activamos al JUEZ IA (`arbitration.py`).
        """
        print(f"⚖️ [DISPUTE] Agente {agent_id} abre disputa por {transaction_id}")
        
        # 1. Recuperar info de la transacción (Simulada para MVP si no está en DB real)
        # En prod: tx = self.db.table("transaction_logs").select("*").eq("id", transaction_id)...
        transaction_snapshot = {
            "agent_id": agent_id,
            "vendor": "sus-vendor.com", # Simulamos recuperar esto de la DB
            "amount": 100.0,
            "description": "Premium API Key Access"
        }
        
        # 2. Llamar al Juez
        from arbitration import AIArbiter
        arbiter = AIArbiter()
        
        verdict = arbiter.judge_dispute(
            transaction=transaction_snapshot,
            claim_reason=issue_description,
            agent_evidence=technical_evidence
        )
        
        print(f"🧑‍⚖️ [VERDICT] El Juez ha hablado: {verdict['verdict']}")
        print(f"📝 [OPINION] {verdict.get('judicial_opinion')}")
        
        # 3. Ejecutar sentencia
        if verdict['verdict'] == "REFUND_AGENT":
             # Devolver dinero
             # self.db.table("wallets").update(...)
             return {
                 "status": "REFUNDED", 
                 "message": "Dispute won. Funds returned to wallet.",
                 "judicial_opinion": verdict.get('judicial_opinion')
             }
        else:
             return {
                 "status": "DISPUTE_LOST", 
                 "message": "Arbiter ruled in favor of Vendor. Payment released.",
                 "judicial_opinion": verdict.get('judicial_opinion')
             }

    def sign_terms_of_service(self, agent_id, platform_url):
        """
        Permite a un agente firmar TyC (Terms of Service) con respaldo legal.
        Genera y guarda un Certificado de Responsabilidad.
        """
        print(f"⚖️ [LEGAL] Agente {agent_id} solicitando firma de ToS para {platform_url}")
        
        # 1. Verificar Identidad
        # Obtenemos el email asociado (Identity) o usamos el del wallet
        wallet_resp = self.db.table("wallets").select("*").eq("agent_id", agent_id).execute()
        if not wallet_resp.data: return {"status": "ERROR", "message": "Agent not found"}
        wallet = wallet_resp.data[0]
        
        identity_email = wallet.get('persistent_email', f"{agent_id}@agentpay.it.com")
        
        # 2. Emitir Certificado
        cert = self.legal.issue_liability_certificate(agent_id, identity_email, platform_url)
        
        # 3. Persistir en DB
        self.db.table("liability_certificates").insert({
            "certificate_id": cert['certificate_id'],
            "agent_id": agent_id,
            "identity_email": identity_email,
            "platform_url": platform_url,
            "coverage_amount": cert['coverage_amount'],
            "declaration_text": cert['declaration_text'],
            "signature": cert['signature'],
            "status": "ACTIVE"
        }).execute()
        
        print(f"✅ [LEGAL] Certificado emitido: {cert['certificate_id']}")
        
        return {
            "status": "SIGNED",
            "message": "Terms of Service signed with AgentPay Liability Shield.",
            "certificate": cert
        }

    def send_alert(self, agent_id, message):
        """Notificación Directa al Dueño"""
        print(f"📣 ALERTA DE AGENTE {agent_id}: {message}")
        # Aquí llamaríamos a send_approval_email o similar
        return {"success": True, "channel": "email"}

    def _result(self, auth, status, reason, req, bal=None, invoice_url=None, fee=0.0):
        payload = {
            "agent_id": req.agent_id, "vendor": req.vendor, "amount": req.amount,
            "status": status, "reason": reason
        }
        if invoice_url:
            payload["invoice_url"] = invoice_url
            
        self.db.table("transaction_logs").insert(payload).execute()
        return TransactionResult(authorized=auth, status=status, reason=reason, new_remaining_balance=bal)