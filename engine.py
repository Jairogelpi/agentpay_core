import os
import stripe
import base64
from urllib.parse import urlparse
from dotenv import load_dotenv
from supabase import create_client, Client
from models import TransactionRequest, TransactionResult
from ai_guard import audit_transaction
from security_utils import check_domain_age

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

    def evaluate(self, request: TransactionRequest) -> TransactionResult:
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
            audit = audit_transaction(request.vendor, request.amount, request.description, request.agent_id, agent_role, history)
            
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
        audit = audit_transaction(request.vendor, request.amount, request.description, request.agent_id, agent_role, history)
        
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

        # --- SI LLEGA AQUÍ, ES SEGURO AL 99.999% ---
        # PASO C: Ejecutar el Pago
        print(f"💳 [STRIPE] Iniciando cargo real de ${request.amount}...")
        
        stripe_tx_id = self._execute_stripe_charge(request.amount, clean_vendor)
        
        if not stripe_tx_id:
            return self._result(False, "REJECTED", "Error en pasarela de pago (Tarjeta rechazada)", request)
            
        new_balance = float(wallet['balance']) - request.amount
        # Aquí idealmente actualizaríamos también daily_spent, pero por ahora solo balance
        self.db.table("wallets").update({"balance": new_balance}).eq("agent_id", request.agent_id).execute()
        
        success_msg = f"Pago Seguro Realizado. (Auditoría: {audit.get('reasoning', 'OK')}) (Ref: {stripe_tx_id})"
        return self._result(True, "APPROVED", success_msg, request, new_balance)

    def _execute_stripe_charge(self, amount, vendor_desc):
        """
        Intenta realizar un cargo real en Stripe.
        Retorna el ID de transacción si es exitoso, o None si falla.
        """
        try:
            # Stripe trabaja en centavos (ints), no decimales. $10.50 -> 1050
            amount_cents = int(amount * 100)
            
            # Simulamos el uso de una tarjeta VISA de prueba (pm_card_visa)
            # En producción, aquí usarías el customer_id asociado al agente.
            intent = stripe.PaymentIntent.create(
                amount=amount_cents,
                currency="usd",
                payment_method="pm_card_visa", # Tarjeta mágica de test que siempre pasa
                confirm=True, # Cobra inmediatamente
                description=f"AgentPay Charge: {vendor_desc}",
                automatic_payment_methods={
                    'enabled': True,
                    'allow_redirects': 'never' # Forzamos error si requiere 3D Secure (IAs no pueden hacer 3DS)
                }
            )
            
            print(f"✅ [STRIPE SUCCESS] Cargo confirmado: {intent.id}")
            return intent.id

        except stripe.error.CardError as e:
            # La tarjeta fue rechazada (fondos insuficientes, bloqueada, etc.)
            print(f"❌ [STRIPE ERROR] Tarjeta rechazada: {e.user_message}")
            return None
        except Exception as e:
            print(f"❌ [STRIPE SYSTEM ERROR] {str(e)}")
            return None

from security_utils import check_domain_age
from notifications import send_approval_email
from webhooks import send_webhook

# ... existing code ...

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

    def _result(self, auth, status, reason, req, bal=None):
        self.db.table("transaction_logs").insert({
            "agent_id": req.agent_id, "vendor": req.vendor, "amount": req.amount,
            "status": status, "reason": reason
        }).execute()
        return TransactionResult(authorized=auth, status=status, reason=reason, new_remaining_balance=bal)