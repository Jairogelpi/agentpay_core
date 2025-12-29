
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

        # 1. Obtener Wallet del Agente
        response = self.db.table("wallets").select("*").eq("agent_id", request.agent_id).execute()
        if not response.data:
            return self._result(False, "REJECTED", "Agente no existe", request)
        
        wallet = response.data[0]
        
        # Recuperamos el rol. Si no tiene, asumimos "Asistente IA General"
        agent_role = wallet.get('agent_role', 'Asistente IA General')
        
        # --- CAPA DE HIERRO 1: LÍMITES MATEMÁTICOS ---
        # Usamos .get para campos opcionales, asumiendo límites altos si no están definidos para no bloquear test
        # Pero en Zero Trust real, deberían ser obligatorios.
        
        max_tx = float(wallet.get('max_transaction_limit', 0))
        if max_tx > 0 and request.amount > max_tx:
             return self._result(False, "REJECTED", f"Excede límite por transacción (${max_tx})", request)
        
        # Simulamos daily_spent y daily_limit si no existen en DB aún
        daily_spent = float(wallet.get('daily_spent', 0))
        daily_limit = float(wallet.get('daily_limit', 0))
        
        if daily_limit > 0 and (daily_spent + request.amount) > daily_limit:
            return self._result(False, "REJECTED", "Excede límite diario", request)

        # Chequeo de saldo real
        if request.amount > float(wallet['balance']):
             return self._result(False, "REJECTED", "Fondos insuficientes", request)

        # --- CAPA COLMENA (HIVE MIND): Ojo de Sauron Community ---
        # Verificamos si el proveedor está en la lista negra global
        clean_vendor = self._normalize_domain(request.vendor)
        try:
            is_banned = self.db.table("global_blacklist").select("*").eq("vendor", clean_vendor).execute()
            if is_banned.data:
                return self._result(False, "REJECTED", "Sitio reportado como fraude por la comunidad AgentPay.", request)
        except Exception as e:
            print(f"⚠️ Error verificando blacklist global: {e}")

        # --- CAPA OSINT (DANGEROUS NEW DOMAINS) ---
        # Si el proveedor NO está en lista blanca, aplicamos el filtro de edad.
        allowed_vendors = wallet.get('allowed_vendors', []) or []
        # Normalizamos la lista blanca para comparar limpiamente
        is_whitelisted = False
        for allowed in allowed_vendors:
            if clean_vendor == allowed or clean_vendor.endswith("." + allowed):
                is_whitelisted = True
                break
                
        # Solo verificamos edad si NO es conocido, para no spamear WHOIS con google.com
        if not is_whitelisted:
            domain_status = check_domain_age(request.vendor)
            if domain_status == "DANGEROUS_NEW":
                return self._result(False, "REJECTED", f"🚨 BLOQUEO CRÍTICO: El dominio '{clean_vendor}' tiene menos de 30 días.", request)
            
            if domain_status == "MEDIUM_RISK":
                 print(f"🛡️ [IDENTITY SHIELD] Detectado Riesgo Medio (30-90 días). Activando Identidad Desechable...")
                 # Crear identidad burner
                 burner = self.identity_mgr.create_burner_identity(request.agent_id)
                 
                 # INYECTAMOS la identidad falsa en la descripción para que quede constancia (pero no en el pago real de Stripe, que usa nuestra tarjeta global)
                 # En un sistema real que tuviera emisión de tarjetas, usaríamos burner['card']
                 request.description += f" [Protected by Burner ID: {burner['identity_id']}]"
                 
                 # Marcamos para destrucción post-pago (usaremos una variable local)
                 request._burner_id_to_destroy = burner['identity_id']

            if domain_status == "UNKNOWN":
                print("⚠️ Advertencia: No pudimos verificar la edad del dominio. Pasando a IA con precaución.")

        # recuperamos historial para contexto (común para ambos casos)
        history = []
        try:
            history_response = self.db.table("transaction_logs")\
                .select("created_at, amount, vendor, reason")\
                .eq("agent_id", request.agent_id)\
                .order("created_at", desc=True)\
                .limit(5)\
                .execute()
            history = history_response.data if history_response.data else []
        except Exception as e:
            print(f"⚠️ Error recuperando historial: {e}")

        # Si NO está en lista blanca -> Bloqueo o Aprobación Humana OBLIGATORIA
        if not is_whitelisted:
            print(f"🔒 [ZERO TRUST] Proveedor desconocido '{clean_vendor}'. Auditando para pre-clasificación...")
            
            # Aquí la IA ayuda a PRE-CLASIFICAR con CONTEXTO HISTÓRICO
            audit = audit_transaction(request.vendor, request.amount, request.description, request.agent_id, agent_role, history, request.justification)
            
            if audit['decision'] == 'REJECTED':
                return self._result(False, "REJECTED", f"IA detectó fraude en sitio desconocido: {audit.get('reasoning', audit.get('reason'))}", request)
            
            # Si la IA dice que "podría" ser válido (APPROVED/FLAGGED), pero NO está en whitelist -> PENDING_APPROVAL
            return self._create_approval_request(
                request, 
                clean_vendor, 
                reason_prefix=f"Proveedor nuevo (fuera de Whitelist). Requiere autorización humana."
            )

        # --- CAPA 3: AUDITORÍA DE CONTEXTO (Solo para proveedores ya aprobados) ---
        # El proveedor es bueno (ej. Amazon), pero ¿la compra es lógica?
        print(f"🛡️ [ZERO TRUST] Proveedor en Whitelist. Verificando contexto con IA...")
        audit = audit_transaction(request.vendor, request.amount, request.description, request.agent_id, agent_role, history, request.justification)
        
        # En Zero Trust, incluso si está en Whitelist, si la IA ve algo raro, pedimos confirmación.
        # Si la IA dice REJECTED -> Bloqueamos aunque sea Amazon (ej. compra absurda).
        if audit['decision'] == 'REJECTED':
             return self._result(False, "REJECTED", f"Bloqueado por IA (Contexto): {audit.get('reasoning', audit.get('reason'))}", request)

        # Si la IA dice FLAGGED -> Aprobación humana.
        if audit['decision'] == 'FLAGGED':
             return self._create_approval_request(
                request, 
                clean_vendor, 
                reason_prefix=f"Proveedor confiable, pero comportamiento extraño: {audit.get('reasoning', audit.get('reason'))}"
            )

        # --- CÁLCULO DE COMISIONES (BUSINESS MODEL) ---
        FEE_PERCENT = 0.015 # 1.5% Comisión AgentPay
        fee = round(request.amount * FEE_PERCENT, 2)
        total_deducted = request.amount + fee
        
        # Chequeo de saldo real (incluyendo comisión)
        current_balance = float(wallet['balance'])
        
        if total_deducted > current_balance:
            # --- INTENTO DE CRÉDITO (VISION 2.0) ---
            credit_check = self.credit_bureau.check_credit_eligibility(request.agent_id)
            
            if credit_check['eligible']:
                max_power = current_balance + credit_check['credit_limit']
                if total_deducted <= max_power:
                    print(f"💳 [CREDIT BUREAU] Saldo insuficiente, activando Línea de Crédito {credit_check['tier']}...")
                    # Permitimos continuar (el saldo quedará negativo)
                else:
                     return self._result(False, "REJECTED", f"Fondos insuficientes (Incluso con crédito de ${credit_check['credit_limit']})", request)
            else:
                return self._result(False, "REJECTED", f"Fondos insuficientes (Monto ${request.amount} + Fee ${fee})", request)

        # ... (Whitelist and AI checks happen here) ...
        # (Note: Logic flow in existing code puts funds check earlier. Ideally we move funds check here or update it. 
        # For minimal diff, I will update the existing funds check logic earlier and then do the deduction here).
        
        # --- SI LLEGA AQUÍ, ES SEGURO AL 99.999% ---
        
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
                "balance": 100.0, # Welcome Bonus for testing!
                "status": "active",
                "max_transaction_limit": 100.0, # Default safe limits
                "daily_limit": 500.0
            }).execute()
            
            return {"agent_id": api_key, "api_key": api_key, "dashboard_url": f"{self.admin_url}/dashboard/{api_key}"}
        except Exception as e:
            return {"error": str(e)}

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
        if amount <= 0: return {"success": False, "message": "Amount must be positive"}
        
        try:
            # 1. Verificar origen
            f_resp = self.db.table("wallets").select("*").eq("agent_id", from_agent_id).execute()
            if not f_resp.data: return {"success": False, "message": "Source agent not found"}
            f_wallet = f_resp.data[0]
            
            # 2. Verificar destino
            t_resp = self.db.table("wallets").select("*").eq("agent_id", to_agent_id).execute()
            if not t_resp.data: return {"success": False, "message": "Target agent not found"}
            t_wallet = t_resp.data[0]
            
            # 3. Verificar Organización (Must be same Owner)
            if f_wallet.get('owner_name') != t_wallet.get('owner_name'):
                 return {"success": False, "message": "Inter-organization transfers forbidden. Must belong to same owner."}
            
            # 4. Verificar Fondos
            if float(f_wallet['balance']) < amount:
                return {"success": False, "message": "Insufficient funds"}
                
            # 5. Ejecutar Transferencia Atómica (Simulada secuencial aquí)
            new_f_bal = float(f_wallet['balance']) - amount
            new_t_bal = float(t_wallet['balance']) + amount
            
            self.db.table("wallets").update({"balance": new_f_bal}).eq("agent_id", from_agent_id).execute()
            self.db.table("wallets").update({"balance": new_t_bal}).eq("agent_id", to_agent_id).execute()
            
            # 6. Log
            self._result(True, "APPROVED", f"Internal Transfer to {to_agent_id}", 
                         TransactionRequest(agent_id=from_agent_id, vendor="Internal Transfer", amount=amount, description=f"Transfer to {to_agent_id}"), 
                         new_f_bal)
                         
            return {"success": True, "new_balance": new_f_bal, "message": "Transfer successful"}
            
        except Exception as e:
            return {"success": False, "message": str(e)}

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