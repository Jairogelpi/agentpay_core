import os
import stripe  # <--- NUEVO
import base64
from urllib.parse import urlparse
from dotenv import load_dotenv
from supabase import create_client, Client
from models import TransactionRequest, TransactionResult

load_dotenv()

# Configuración inicial de Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY") # <--- NUEVO

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

        # 1. Obtener Estado (Igual que antes)
        response = self.db.table("wallets").select("*").eq("agent_id", request.agent_id).execute()
        if not response.data:
            return self._result(False, "REJECTED", "Agente no existe", request)
        
        wallet = response.data[0]
        
        # 2. Normalización DNS y Whitelist (Igual que antes)
        clean_vendor = self._normalize_domain(request.vendor)
        is_allowed = False
        allowed_list = wallet.get('allowed_vendors', []) or []
        for allowed in allowed_list:
            if clean_vendor == allowed or clean_vendor.endswith("." + allowed):
                is_allowed = True
                break
        
        # Fallback del 1% (Magic Link)
        if not is_allowed:
            return self._create_approval_request(request, clean_vendor)

        # 3. Reglas Financieras Internas (Budget Check)
        if request.amount > float(wallet['max_transaction_limit']):
            return self._result(False, "REJECTED", f"Excede límite (${wallet['max_transaction_limit']})", request)

        if request.amount > float(wallet['balance']):
             return self._result(False, "REJECTED", "Fondos insuficientes en AgentPay", request)

        # --- AQUÍ EMPIEZA LA MAGIA DE STRIPE ---
        print(f"💳 [STRIPE] Iniciando cargo real de ${request.amount}...")
        
        stripe_tx_id = self._execute_stripe_charge(request.amount, clean_vendor)
        
        if not stripe_tx_id:
            # Si Stripe falla, NO restamos saldo y devolvemos error.
            return self._result(False, "REJECTED", "Error en pasarela de pago (Tarjeta rechazada)", request)
            
        # ---------------------------------------

        # 4. Persistencia (Solo si Stripe aprobó)
        new_balance = float(wallet['balance']) - request.amount
        self.db.table("wallets").update({"balance": new_balance}).eq("agent_id", request.agent_id).execute()
        
        # Guardamos el ID de Stripe en los logs para referencia futura
        success_msg = f"Pago autorizado a {clean_vendor} (Ref: {stripe_tx_id})"
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

    # ... Resto de métodos auxiliares (_normalize_domain, _create_approval_request, _result) IGUALES QUE ANTES ...
    def _normalize_domain(self, vendor_str: str) -> str:
        vendor_str = vendor_str.lower().strip()
        if not vendor_str.startswith(('http://', 'https://')):
            vendor_str = 'https://' + vendor_str
        parsed = urlparse(vendor_str)
        domain = parsed.netloc or parsed.path
        if domain.startswith("www."): domain = domain[4:]
        return domain

    def _create_approval_request(self, request, clean_vendor):
        payload = f"{request.agent_id}:{clean_vendor}"
        token = base64.b64encode(payload.encode()).decode()
        magic_link = f"{self.admin_url}/admin/approve?token={token}"
        print(f"⚠️  [UNKNOWN VENDOR] Generando solicitud de aprobación: {magic_link}")
        return TransactionResult(authorized=False, status="PENDING_APPROVAL", reason=f"Proveedor nuevo. Aprobación requerida.", approval_link=magic_link)

    def _result(self, auth, status, reason, req, bal=None):
        self.db.table("transaction_logs").insert({
            "agent_id": req.agent_id, "vendor": req.vendor, "amount": req.amount,
            "status": status, "reason": reason
        }).execute()
        return TransactionResult(authorized=auth, status=status, reason=reason, new_remaining_balance=bal)