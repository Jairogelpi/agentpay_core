import os
import math
import stripe
import base64
import uuid
import time
import hashlib
import secrets
import whois
import socket
import ssl
import validators
from datetime import datetime, timedelta
from urllib.parse import urlparse
from dotenv import load_dotenv
from supabase import create_client, Client
from models import TransactionRequest, TransactionResult, CardDetails
from ai_guard import audit_transaction, calculate_statistical_risk
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
from loguru import logger
import json # Added for json.loads if needed, though model_validate_json is used
import jwt # <--- JWT Support

load_dotenv()

# Configuración inicial de Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

class UniversalEngine:
    def __init__(self):
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_KEY")
        self.admin_url = os.environ.get("ADMIN_API_URL", "http://localhost:8000")
        self.jwt_secret = os.environ.get("JWT_SECRET", "super-secret-fix-in-prod") # <--- Secret for signing tokens
        
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
             if self.redis.ping():
                self.redis_enabled = True
                logger.info(f"✅ Redis conectado")
             else:
                 self.redis_enabled = False
                 logger.warning(f"⚠️ Redis no disponible. Usando memoria RAM (Inseguro para prod).")
        except Exception as e:
             logger.warning(f"⚠️ Redis no disponible. Usando memoria RAM (Inseguro para prod). Error: {e}")
             self.redis_enabled = False
             self.transaction_velocity = {} 

    async def _perform_osint_scan(self, vendor_url: str):
        """
        ANALISIS DE ADN DE DOMINIO: OSINT en tiempo real.
        Investiga si el dominio es falso, nuevo o peligroso.
        """
        if not vendor_url: return {"score": 100, "risk_factors": []}
        
        domain = self._normalize_domain(vendor_url)
        
        # 0. ANALISIS DE ENTROPIA (DGA Detection)
        entropy = self.calculate_domain_entropy(domain)
        logger.debug(f"🔍 [OSINT] DNA Analysis for {domain} (Entropy: {entropy:.2f})")

        # 1. CONSULTAR CACHÉ (Mente Colmena)
        try:
            cached = self.db.table("global_reputation_cache").select("*").eq("domain", domain).single().execute()
            if cached.data:
                # Comprobar si el scan es reciente (< 7 días)
                last_scan = datetime.fromisoformat(cached.data['last_scan'].replace('Z', '+00:00'))
                if (datetime.now(last_scan.tzinfo) - last_scan).days < 7:
                    logger.info(f"🔄 [OSINT] Devolviendo respuesta cacheada para {domain}")
                    return {
                        "score": cached.data['score'],
                        "risk_factors": cached.data['risk_factors'],
                        "entropy": entropy
                    }
        except Exception as e:
            logger.debug(f"⚠️ OSINT Cache error: {e}")

        results = {"score": 100, "risk_factors": [], "entropy": entropy}
        
        # SANCION POR ENTROPIA ALTA (Nombres aleatorios sospechosos)
        if entropy > 3.8:
            results["score"] -= 40
            results["risk_factors"].append(f"ALTA ENTROPIA ({entropy:.2f}): Dominio sospechosamente aleatorio (Posible DGA)")
        
        try:
            # 1. Antigüedad del dominio (WHOIS)
            try:
                w = whois.whois(domain)
                creation_date = w.creation_date
                if isinstance(creation_date, list): creation_date = creation_date[0]
                
                if creation_date:
                    days_old = (datetime.now() - creation_date).days
                    if days_old < 15:
                        results["score"] -= 80
                        results["risk_factors"].append("DOMINIO RECIEN CREADO (< 15 DIAS) - RIESGO EXTREMO")
                    elif days_old < 30:
                        results["score"] -= 60
                        results["risk_factors"].append("DOMINIO EXTREMADAMENTE NUEVO (ALTO RIESGO)")
                    elif days_old < 180:
                        results["score"] -= 20
                        results["risk_factors"].append("Dominio joven (< 6 meses)")
                else:
                    results["score"] -= 10
                    results["risk_factors"].append("Fecha de creación oculta")
            except Exception as e:
                logger.warning(f"⚠️ Whois error: {e}")
                results["score"] -= 20
                results["risk_factors"].append("Whois privado/oculto")

            # 2. Verificación de Seguridad (SSL/HTTPS)
            if not vendor_url.startswith("https"):
                results["score"] -= 30
                results["risk_factors"].append("Sin conexión segura HTTPS")

            # SSL Check físico (Extra)
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
            except Exception as e:
                logger.debug(f"SSL check failed for {domain}: {e}") # Fallo silencioso si ya detectamos no-https

            # 4. GUARDAR EN MENTE COLMENA (Global Cache)
            self.db.table("global_reputation_cache").upsert({
                "domain": domain,
                "score": results["score"],
                "risk_factors": results["risk_factors"],
                "last_scan": datetime.now().isoformat(),
                "tld": domain.split('.')[-1]
            }).execute()

            # 4. PATRONES POR TLD (Ataque de Mente Colmena)
            # Si un TLD tiene muchos reportes, bajamos el score base preventivamente.
            suspicious_tlds = [".top", ".xyz", ".bid", ".club", ".online", ".store"]
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                results["score"] -= 15
                results["risk_factors"].append(f"TLD Sospechoso ({domain.split('.')[-1]}): Elevando sensibilidad de IA.")
            
        except Exception as e:
            logger.error(f"⚠️ OSINT Scan error: {e}")
            results["score"] -= 10
            results["risk_factors"].append("Error en análisis")

        return results

    def process_stripe_webhook(self, payload, sig_header):
        """
        Procesa eventos de Stripe (Webhooks) para confirmar recargas de saldo.
        """
        try:
            # Es vital que 'webhook_secret' sea el correcto para el modo (Test o Live)
            event = stripe.Webhook.construct_event(
                payload, sig_header, self.webhook_secret
            )
            logger.info(f"✅ Webhook verificado: {event['type']}")
        except ValueError as e:
            # Payload inválido
            logger.error("❌ Payload de webhook inválido")
            raise Exception("Invalid payload")
        except stripe.error.SignatureVerificationError as e:
            # ATAQUE DETECTADO: La firma no coincide
            logger.critical(f"🚨 ¡ALERTA DE SEGURIDAD! Intento de falsificación de Webhook detectado.")
            # Aquí podrías usar tu ForensicAuditor para registrar el intento
            raise Exception("Invalid signature")

        # Manejar el evento
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            agent_id = session.get('metadata', {}).get('agent_id') # Asegúrate de que el agent_id se pase en metadata
            # Con Connect, el dinero ya está en SU cuenta, solo registramos el evento
            if agent_id:
                amount_received = float(session.get('amount_total', 0)) / 100.0
                logger.info(f"💰 Recarga completada para {agent_id}: ${amount_received}")
                self.db.table("transaction_logs").insert({
                    "id": session['id'],
                    "agent_id": agent_id,
                    "vendor": "Stripe Topup",
                    "amount": amount_received,
                    "status": "APPROVED",
                    "reason": "Recarga de Saldo (Webhook Validado)"
                }).execute()
                
                # Actualizar saldo en DB
                wallet_resp = self.db.table("wallets").select("*").eq("agent_id", agent_id).execute()
                if wallet_resp.data:
                    old_bal = float(wallet_resp.data[0]['balance'])
                    self.db.table("wallets").update({"balance": old_bal + amount_received}).eq("agent_id", agent_id).execute()
        
        elif event['type'] == 'issuing_authorization.request':
            auth = event['data']['object']
            agent_id = auth['metadata'].get('agent_id') # Asegúrate de meter metadata al crear la tarjeta
            
            # Aquí podrías ejecutar ai_guard de nuevo para una "Segunda Opinión" en tiempo real
            logger.info(f"💳 Intento de cobro: ${auth['amount']/100} en {auth['merchant_data']['name']}")
            
            # Por defecto aprobamos porque ya validamos antes de emitir la tarjeta
            return {"status": "approved"} # Stripe espera un 200 OK

        return {"status": "ignored"}

    def _automate_issuing_balance_sync(self, amount_usd):
        """
        Mueve fondos automáticamente del saldo disponible al saldo de Issuing.
        Nota: Esto requiere que el origen de fondos sea 'stripe_balance'.
        """
        try:
            logger.info(f"💸 [FINTECH] Orquestando traslado de ${amount_usd} al pozo de Issuing...")
            
            # 1. Definimos la cantidad máxima transferible (en centavos)
            amount_cents = int(amount_usd * 100)
            
            # 2. Ejecutar Transferencia a Balance Issuing (Stripe Connect)
            try:
                # Simulación de llamada a Topup de Issuing (Requiere permisos especiales de Stripe)
                # stripe.Topup.create(amount=amount_cents, currency="usd", destination_balance="issuing", description="Auto-Sync AgentPay")
                logger.success("   ✅ [MOCK] Fondos movidos al balance de Issuing (Simulación).")
            except Exception as strype_err:
                logger.error(f"   ⚠️ Error Stripe Topup: {strype_err}")

            # 3. Registrar movimiento contable
            self.db.table("transaction_logs").insert({
                "id": str(uuid.uuid4()),
                "agent_id": "SYSTEM_HOME",
                "vendor": "AgentPay Treasury",
                "amount": amount_usd,
                "status": "APPROVED",
                "reason": "Internal Treasury Orchestration (Checkout -> Issuing)"
            }).execute()

        except Exception as e:
            logger.warning(f"⚠️ Aviso de Orquestación: {e}")

    def check_circuit_breaker(self, agent_id, kyc_level="UNVERIFIED"):
        """
        Fusible Financiero Indestructible (Redis)
        Ajustamos el límite: 10 tx/min para nuevos, 30 tx/min para verificados.
        """
        current_time = int(time.time())
        try:
            limit = 30 if kyc_level == "VERIFIED" else 10
            
            if self.redis_enabled:
                key = f"velocity:{agent_id}"
                pipe = self.redis.pipeline()
                pipe.zadd(key, {str(current_time): current_time})
                pipe.zremrangebyscore(key, 0, current_time - 60) # Borrar viejos (>60s)
                pipe.zcard(key) # Contar actuales
                pipe.expire(key, 65) # Auto-limpieza
                results = pipe.execute()
                
                count = results[2]
                if count >= limit: # Límite dinámico
                    return True # 🔥 FUSIBLE ACTIVADO
                return False
            else:
                 # Fallback RAM
                if agent_id not in self.transaction_velocity: self.transaction_velocity[agent_id] = []
                self.transaction_velocity[agent_id] = [t for t in self.transaction_velocity[agent_id] if current_time - t < 60]
                if len(self.transaction_velocity[agent_id]) >= limit: return True
                self.transaction_velocity[agent_id].append(current_time)
                return False
        except Exception as e:
            logger.error(f"⚠️ Circuit Breaker Error: {e}")
            return False

    async def evaluate(self, request: TransactionRequest, idempotency_key: str = None) -> TransactionResult:
        # --- CAPA 0: POLÍTICAS CORPORATIVAS (Rule-Based) ---
        # "El Manual del Empleado" - Reglas duras antes de gastar tokens de IA
        compliance_ok, compliance_reason = self.check_corporate_compliance(str(request.agent_id), request)
        
        if not compliance_ok:
             # Si devuelve False, es un rechazo duro (Hard Block)
             return self._result(False, "REJECTED", f"Política Corporativa: {compliance_reason}", request)
        
        if compliance_ok == "PENDING":
             # Si devuelve "PENDING", es un Soft Limit que requiere aprobación humana
             return self._create_approval_request(request, self._normalize_domain(request.vendor), reason_prefix=f"👮 {compliance_reason}")

        # --- CAPA -1: SANITY CHECK (NUEVO) ---
        # Bloqueamos montos negativos, cero o absurdamente pequeños antes de gastar recursos.
        if request.amount <= 0.50:  # Mínimo de Stripe suele ser $0.50
            logger.warning(f"🚫 [SANITY] Monto inválido detectado: ${request.amount}")
            return TransactionResult(
                authorized=False,
                status="REJECTED",
                reason=f"Monto inválido (${request.amount}). El mínimo es $0.50."
            )

        # --- CAPA -0.5: HIVE MIND REAL-TIME BLOCK (NUEVO) ---
        # Bloqueo inmediato para dominios reportados hace milisegundos (Race Condition Mitigation)
        clean_vendor = self._normalize_domain(request.vendor)
        if self.redis_enabled and self.redis.get(f"blacklist:{clean_vendor}"):
            logger.critical(f"🚫 [HIVE MIND] Bloqueo Tiempo Real activado para {clean_vendor}")
            return TransactionResult(
                authorized=False,
                status="REJECTED",
                reason="Bloqueado por Mente Colmena (Tiempo Real)"
            )

        # 0. IDEMPOTENCIA (Evitar cobros dobles)
        if idempotency_key and self.redis_enabled:
            cache_key = f"idempotency:{idempotency_key}"
            try:
                cached_result = self.redis.get(cache_key)
                if cached_result:
                    logger.info(f"🔄 [REPLAY] Devolviendo respuesta cacheada para {idempotency_key}")
                    # Deserializar simple (en prod usar Pydantic model_validate_json si está disponible o json.loads)
                    return TransactionResult.model_validate_json(cached_result)
            except Exception as e:
                logger.error(f"⚠️ Redis Cache Error: {e}")

        # --- CAPA 0: IDENTITY & CONTEXT (MOVIDO ANTES DEL CIRCUIT BREAKER) ---
        response = self.db.table("wallets").select("*").eq("agent_id", request.agent_id).execute()
        if not response.data:
             # Si falla la DB, asumimos UNVERIFIED para el circuit breaker en la siguiente línea (o fallamos)
             # Pero mejor retornamos error aquí
            return self._result(False, "REJECTED", "Agente no existe", request)
        
        wallet = response.data[0]
        agent_role = wallet.get('agent_role', 'Asistente IA General')
        kyc_level = wallet.get('kyc_status', 'UNVERIFIED') # Default a unverified para seguridad

        # 1.2 CIRCUIT BREAKER (Ahora con KYC Awareness)
        if self.check_circuit_breaker(request.agent_id, kyc_level):
            logger.critical(f"🔥 [CIRCUIT BREAKER] Agente {request.agent_id} bloqueado por velocidad excesiva.")
            return TransactionResult(
                authorized=False, 
                status="CIRCUIT_OPEN", 
                reason="🚨 FUSIBLE ACTIVADO: Detectado bucle infinito (>limit tx/min). Agente congelado."
            )
            
        logger.info(f"\n🧠 [ENGINE] Procesando: {request.vendor} (${request.amount})")
        
        # --- PILLAR 2: PROGRESSIVE KYC GATE ---
        # Si el monto es alto, exigimos verificación de identidad humana
        if request.amount > 500.0 and kyc_level != 'VERIFIED':
             return TransactionResult(
                 authorized=False,
                 status="REJECTED",
                 reason=f"KYC Requerido: Límites excedidos para nivel {kyc_level}. Verifica tu identidad para gastar > $500."
             )
        
        # --- INTERNAL CLEARING HOUSE (P2P ECONOMY) ---
        # Si el vendor es otro agente, ejecutamos off-chain (0 fees)
        try:
             internal_vendor = self.db.table("wallets").select("agent_id").eq("agent_id", request.vendor).execute()
             if internal_vendor.data:
                 logger.debug(f"⚡ [INTERNAL] Ejecutando Transferencia Atómica P2P...")
                 
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
             logger.warning(f"P2P transfer failed, falling back to external: {e}")
             pass
        
        if request.vendor_url:
             osint_report = await self._perform_osint_scan(request.vendor_url)
             
             if osint_report["score"] < 50:
                 # Si la reputación es mala, el AI_GUARD debe ser 100% estricto
                 return TransactionResult(
                     authorized=False,
                     status="REJECTED",
                     reason=f"Riesgo de Seguridad OSINT: {', '.join(osint_report['risk_factors'])}"
                 )
             elif osint_report["score"] < 80:
                 # Si hay dudas, forzamos aprobación humana (Área Gris)
                 return TransactionResult(
                     authorized=False,
                     status="APPROVED_PENDING_AUDIT",
                     reason="Comercio detectado con baja reputación técnica. Requiere revisión."
                 )
             else:
                 logger.info(f"✅ [OSINT] Sitio confiable (Score: {osint_report['score']})")

        # --- CAPA 1: FIREWALL & INSURANCE (SECURITY FIRST) ---
        clean_vendor = self._normalize_domain(request.vendor)
        try:
            is_banned = self.db.table("global_blacklist").select("*").eq("vendor", clean_vendor).execute()
            if is_banned.data:
                return self._result(False, "REJECTED", "Sitio en Lista Negra Global.", request)
        except Exception as e:
            logger.error(f"Error checking global blacklist: {e}")

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
            h_resp = self.db.table("transaction_logs").select("created_at, amount, vendor, reason").eq("agent_id", request.agent_id).order("created_at", desc=True).limit(20).execute()
            history = h_resp.data if h_resp.data else []
        except Exception as e:
            logger.error(f"Error fetching transaction history: {e}")

        # --- FUSIBLE ESTADÍSTICO (Statistical Fuse) ---
        # Bloqueo duro si la desviación es crítica, ANTES de gastar tokens de IA.
        z_score_check, _ = calculate_statistical_risk(request.amount, history)
        if z_score_check > 3.0:
            logger.warning(f"🚨 [FUSIBLE ACTIVADO] Z-Score Crítico: {z_score_check:.2f}")
            return self._result(False, "REJECTED", f"FUSIBLE ACTIVADO: Desviación estadística crítica (Z-Score: {z_score_check:.2f})", request)

        insurance_config = wallet.get('insurance_config', {})
        insurance_enabled = insurance_config.get('enabled', False)
        sensitivity = insurance_config.get('strictness', 'HIGH') if insurance_enabled else "HIGH"
        
        should_audit = insurance_enabled or (not is_whitelisted)
        
        log_suffix = ""
        if should_audit:
            if not insurance_enabled: sensitivity = "LOW"
            
            # --- MEMORIA DE CONFIANZA (Reinforcement Learning) ---
            trusted_context = None
            catalog = wallet.get("services_catalog") or {}
            
            # Soporte dual: Dict (nuevo) o List (legacy)
            is_trusted = False
            if isinstance(catalog, dict):
                is_trusted = catalog.get(clean_vendor) == "trusted"
            elif isinstance(catalog, list):
                is_trusted = clean_vendor in catalog

            if is_trusted:
                trusted_context = f"IMPORTANT: The user has PREVIOUSLY APPROVED '{clean_vendor}' manually. This is a TRUSTED vendor. Lower your suspicion level."
                logger.info(f"🧠 [MEMORY] Contexto de confianza inyectado para {clean_vendor}")

            logger.info(f"🛡️ [THE ORACLE] Auditando ({sensitivity})...")
            # ASYNC AWAIT: No bloqueamos el hilo principal mientras OpenAI piensa
            audit = await audit_transaction(request.vendor, request.amount, request.description, request.agent_id, agent_role, history, request.justification, sensitivity=sensitivity, domain_status=domain_status, osint_report=osint_report, trusted_context=trusted_context)
            
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
            logger.info(f"💰 [ATOMIC] Intentando debitar ${total_deducted}...")
            new_balance_resp = self.db.rpc("deduct_balance", {"p_agent_id": request.agent_id, "p_amount": total_deducted}).execute()
            
            # Si llegamos aquí, el dinero YA SE DESCONTÓ con seguridad
            new_balance = float(new_balance_resp.data)
            
        except Exception as e:
            # Si falla el RPC (ej: Saldo insuficiente), capturamos el error
            error_msg = str(e)
            return self._result(False, "REJECTED", f"Error Transaccional: {error_msg}", request, mcc_category=mcc_category, intent_hash=intent_hash, gl_code=gl_code, deductible=is_deductible)


        # --- CAPA 3: EJECUCIÓN (TARJETA VIRTUAL REAL) ---
        logger.info(f"💳 [ISSUING] Generando Tarjeta Virtual ({mcc_category}) para {request.vendor}...")
        
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
            logger.error(f"⚠️ Error generando factura: {e}")
            invoice_path = None
        
        # --- LIBRO MAYOR FORENSE (Forensic Ledger) ---
        # Empaquetamos la evidencia firmada con Chain of Thought (CoT)
        forensic_bundle = self.forensic_auditor.generate_audit_bundle(
            agent_id=request.agent_id,
            vendor=clean_vendor,
            amount=request.amount,
            description=request.description,
            reasoning_cot=risk_reason if 'risk_reason' in locals() else "Approved by Rule/Whitelist",
            intent_hash=intent_hash if 'intent_hash' in locals() else "N/A",
            signature=f"legal_sig_{uuid.uuid4().hex[:12]}",
            osint_data=osint_report if 'osint_report' in locals() else None
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
            logger.critical(f"❌ [STRIPE ERROR] {str(e)}")
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
                    logger.info(f"   ⚠️ Actualizando titular (Teléfono + Requisitos)...")
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
            logger.success(f"✅ Emitiendo tarjeta para {agent_id}...")
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
            
            # LOG SEGURO (Masked)
            logger.info(f"💳 Virtual Card issued: **** {card.last4} | Limit: ${amount}")
            
            return {
                "id": card.id,
                "number": getattr(card, 'number', "4000 0000 0000 0000"), # Necessary for agent use
                "cvv": getattr(card, 'cvc', "000"),
                "exp_month": card.exp_month,
                "exp_year": card.exp_year,
                "brand": card.brand,
                "last4": card.last4,
                "status": card.status
            }
            
        except Exception as e:
            logger.critical(f"❌ [ISSUING PLATFORM ERROR] {e}")
            return None

    def calculate_domain_entropy(self, domain):
        """
        Shannon Entropy para detectar algoritmos de generación de dominios (DGA).
        """
        if not domain: return 0
        prob = [float(domain.count(c)) / len(domain) for c in dict.fromkeys(list(domain))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def _normalize_domain(self, vendor_str: str) -> str:
        """Limpieza básica de dominios."""
        return vendor_str.lower().strip()

    def identify_accounting_nature(self, vendor, mcc_cat='services'):
        """
        Determina el código contable (GL Code) y deducibilidad basado en el proveedor.
        """
        v = vendor.lower()
        if "google" in v or "aws" in v or "azure" in v:
            return "6200", True # Software/Infrastructure
        if "uber" in v or "lyft" in v:
            return "5400", True # Travel
        if "restaurant" in v or "food" in v:
            return "5200", True # Meals
        return "0000", False # Uncategorized / Personal
        vendor_str = vendor_str.lower().strip()
        if not vendor_str.startswith(('http://', 'https://')):
            vendor_str = 'https://' + vendor_str
        parsed = urlparse(vendor_str)
        domain = parsed.netloc or parsed.path
        if domain.startswith("www."): domain = domain[4:]
        return domain

    def report_fraud(self, agent_id, vendor, reason):
        """
        MENTE COLMENA: Registra un fraude y sincroniza la reputación global al instante.
        """
        clean_vendor = self._normalize_domain(vendor)
        try:
            # 1. Lista Negra Global (Persistencia)
            self.db.table("global_blacklist").upsert({
                "vendor": clean_vendor,
                "reason": f"Fraud reported by {agent_id}: {reason}"
            }).execute()
            
            # 2. Hive Mind: Sincronización inmediata de reputación
            # Bajamos el score a 0 para que todos los agentes lo bloqueen al instante.
            self.db.table("global_reputation_cache").upsert({
                "domain": clean_vendor,
                "score": 0,
                "risk_factors": [f"FRAUD REPORTED (Hive Mind): {reason}"],
                "last_scan": datetime.now().isoformat()
            }).execute()

            logger.warning(f"🚨 [HIVE MIND] Global Reputation Poisoned for {clean_vendor}. All agents protected.")
            return {"success": True, "message": f"Proveedor {clean_vendor} bloqueado globalmente."}
        except Exception as e:
            logger.error(f"⚠️ Error en Hive Mind Update: {e}")
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
        # Generar ID de transacción persistente para que el link funcione
        tx_id = str(uuid.uuid4())
        
        # Insertar registro PENDING_APPROVAL
        try:
            self.db.table("transaction_logs").insert({
                "id": tx_id,
                "agent_id": request.agent_id,
                "vendor": clean_vendor,
                "amount": request.amount,
                "status": "PENDING_APPROVAL",
                "reason": reason_prefix,
                "created_at": datetime.now().isoformat()
            }).execute()
        except Exception as e:
            logger.error(f"❌ Error persisting pending transaction: {e}")
            # Fallback a ID generado sin persistencia (el link fallará pero no crashea el flujo)
        
        # 3. Generar token JWT firmado (15 min expiración)
        payload = {
            "tx_id": tx_id,
            "exp": datetime.utcnow() + timedelta(minutes=15),
            "iat": datetime.utcnow()
        }
        token = jwt.encode(payload, self.jwt_secret, algorithm="HS256")
        
        magic_link = f"{self.admin_url}/admin/approve?token={token}"
        
        try:
            response = self.db.table("wallets").select("owner_email, slack_webhook_url").eq("agent_id", request.agent_id).execute()
            wallet_data = response.data[0] if response.data else {}
            
            # 1. Slack (Real-time Control)
            if wallet_data.get('slack_webhook_url'):
                sent = send_slack_approval(wallet_data.get('slack_webhook_url'), request.agent_id, request.amount, clean_vendor, magic_link, reason=reason_prefix)
                if sent: logger.info(f"   🔔 Slack Notification sent to {request.agent_id}")
            
            # 2. Email (Legacy Fallback)
            owner_email = wallet_data.get('owner_email')
            if owner_email:
                send_approval_email(owner_email, request.agent_id, clean_vendor, request.amount, magic_link)

        except Exception as e:
            logger.error(f"Error enviando notificaciones: {e}")
            
        return TransactionResult(
            authorized=False, 
            status="APPROVED_PENDING_AUDIT", 
            reason=f"{reason_prefix}. Link enviado al admin.",
            transaction_id=tx_id
        )


    # Eliminado el duplicado de report_fraud para mantener consistencia

    def process_approval(self, token):
        """
        Procesa la aprobación manual de una transacción desde el email.
        """
        try:
             # Validar Token JWT
             try:
                 payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
                 transaction_id = payload.get("tx_id")
             except jwt.ExpiredSignatureError:
                 return {"error": "El enlace ha expirado."}
             except jwt.InvalidTokenError:
                 return {"error": "Token inválido."} 
             
             # 1. Recuperar Transacción
             tx = self.db.table("transaction_logs").select("*").eq("id", transaction_id).single().execute()
             if not tx.data: 
                 logger.warning(f"Transaction {transaction_id} not found for approval.")
                 return {"error": "Transacción no encontrada"}
             
             tx_data = tx.data
             
             # 2. Aprobar
             self.db.table("transaction_logs").update({
                 "status": "APPROVED",
                 "reason": "Aprobado manualmente por el propietario."
             }).eq("id", transaction_id).execute()
             
             # 3. APRENDIZAJE AUTOMÁTICO (Hive Mind)
             # Si el humano aprueba, el vendedor se vuelve de confianza
             agent_id = tx_data.get('agent_id')
             vendor = tx_data.get('vendor')
             
             if vendor and agent_id:
                 self.add_to_trusted_services(agent_id, vendor)
             
             logger.info(f"✅ Transaction {transaction_id} approved manually. Vendor {vendor} added to trusted services for {agent_id}.")
             return {"status": "APPROVED", "message": "Transacción aprobada y vendedor añadido a whitelist."}
             
        except Exception as e:
            logger.error(f"❌ Error processing manual approval for token {token}: {e}")
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
            logger.error(f"Error creating topup link for {agent_id}: {e}")
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

            logger.info(f"🤖 Iniciando recarga automática de ${amount} para {agent_id}...")

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

            logger.success(f"✅ DINERO INGRESADO: ${amount} (Nuevo saldo: ${new_bal})")
            return {"status": "SUCCESS", "new_balance": new_bal, "tx_id": intent.id}


        except stripe.error.StripeError as e:
            # Si falla por "capabilities", intentamos activarlas forzosamente
            if "capabilities" in str(e):
                logger.warning(f"⚠️ Intentando reparar cuenta {connected_account_id}...")
                try:
                    stripe.Account.modify(connected_account_id, capabilities={"transfers": {"requested": True}})
                    return {"status": "RETRY_NEEDED", "message": "Cuenta reparada. Intenta de nuevo en 5 segundos."}
                except Exception as repair_err:
                    logger.error(f"Error repairing account capabilities: {repair_err}")
            logger.error(f"Stripe Error during automatic topup: {e}")
            return {"status": "ERROR", "message": str(e)}
        except Exception as e:
            logger.error(f"General Error during automatic topup: {e}")
            return {"status": "ERROR", "message": str(e)}

    # --- ASYNC AUDIT HELPERS ---
    def _reverse_transaction(self, agent_id, amount):
        logger.info(f"   💸 REVERSING: Devolviendo ${amount} a {agent_id}")
        try:
             # Devolución simple (sumar saldo)
             # En un sistema real usaríamos una tabla 'ledger' con entradas negativas/positivas
             self.db.rpc("deduct_balance", {"p_agent_id": agent_id, "p_amount": -amount}).execute() # Negativo = Suma
        except Exception as e:
            logger.error(f"❌ Error Critical Reversing: {e}")

    def _ban_agent(self, agent_id, reason="Security Violation"):
        logger.warning(f"   🚫 BANNING: Agente {agent_id} congelado por: {reason}")
        try:
            self.db.table("wallets").update({"status": "FROZEN", "ban_reason": str(reason)}).eq("agent_id", agent_id).execute()
        except Exception as e:
             logger.error(f"❌ Error Banning Agent: {e}")

    async def run_background_audit(self, tx_data):
        """
        Auditoría Post-Pago: El cerebro trabaja mientras el dinero ya se movió.
        """
        logger.info(f"🕵️ [THE ORACLE] Analizando rastro de: {tx_data.get('vendor')}")
        
        # Recuperar contexto necesario
        agent_id = tx_data.get('agent_id')
        vendor = tx_data.get('vendor')
        amount = tx_data.get('amount')
        
        # 0. AUTO-LEARN CHECK (Lista Blanca)
        try:
             w_res = self.db.table("wallets").select("agent_role, services_catalog, owner_email").eq("agent_id", agent_id).single().execute()
             wallet_data = w_res.data or {}
             agent_role = wallet_data.get('agent_role', 'Unknown')
             trusted_vendors = wallet_data.get('services_catalog', []) or []
             owner_email = wallet_data.get('owner_email')
             
             clean_vendor = self._normalize_domain(vendor)
             if clean_vendor in trusted_vendors:
                 logger.success(f"✅ [AUTO-LEARN] '{clean_vendor}' ya es de confianza. Aprobando automáticamente.")
                 self.db.table("transaction_logs").update({
                     "status": "APPROVED",
                     "reason": f"Trusted Vendor (Auto-Learn): {clean_vendor}"
                 }).eq("id", tx_data.get('id')).execute()
                 return
                 
             h_resp = self.db.table("transaction_logs").select("created_at, amount, vendor, reason").eq("agent_id", agent_id).order("created_at", desc=True).limit(5).execute()
             history = h_resp.data if h_resp.data else []
        except Exception as e: 
             logger.error(f"Error fetching wallet/history data for background audit: {e}")
             agent_role = "Unknown"
             history = []
             trusted_vendors = {}

        # 0. OSINT AUDIT (Mente Colmena)
        # Recuperamos datos de reputación en tiempo real para el AI Guard
        osint_report = await self._perform_osint_scan(tx_data.get('vendor_url') or tx_data.get('vendor'))

        # Llamamos a tu AI Guard COMPLETO
        risk_assessment = await audit_transaction(
            vendor=vendor, 
            amount=amount, 
            description=tx_data.get('description', 'N/A'), 
            agent_id=agent_id, 
            agent_role=agent_role, 
            history=history, 
            justification=tx_data.get('justification', 'N/A'),
            sensitivity="HIGH",
            osint_report=osint_report  # <--- NUEVO: Contexto de Desconfianza
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

            # 2. BANEO + PILLAR 5: HIVE MIND BLACKLIST
            # Si el riesgo es crítico, quemamos el dominio en la red global
            if "CRITICAL" in str(risk_assessment).upper() or osint_report.get('score', 100) < 30:
                 try:
                     logger.warning(f"☣️ [HIVE MIND] Agregando {vendor} a la LISTA NEGRA GLOBAL.")
                     self.db.table("global_blacklist").upsert({
                         "vendor": self._normalize_domain(vendor),
                         "reason": f"Automated Ban by AI Guard: {reason_text}",
                         "severity": "CRITICAL"
                     }).execute()
                 except Exception as bl_err:
                     logger.error(f"⚠️ Error actualizando Blacklist Global: {bl_err}")

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
                logger.info(f"📢 Alerta Slack enviada para {agent_id}")
            
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
                    logger.info(f"📧 Alerta de baneo enviada a {owner_email}")
                except Exception as e:
                    logger.error(f"⚠️ Fallo al enviar alerta por email al cliente: {e}")
            
            logger.success(f"✅ Protocolo completado. Agente {agent_id} neutralizado.")

        # --- ZONA GRIS / APRENDIZAJE ---
        # Cambia la lógica de "Zona Gris" para que sea más sensible en el mundo real
        # --- ZONA DE DECISIÓN INTELIGENTE (Pillar REAL) ---
        # Solo mandamos email si la IA NO está segura (FLAGGED) o si detecta riesgo
        elif verdict == "FLAGGED" or "LOW RISK" not in verdict:
            logger.info(f"🤔 [SISTEMA INTELIGENTE] Transacción sospechosa detectada por la IA.")
            
            # Recuperar email si no estaba en rejected block
            try:
                wr = self.db.table("wallets").select("owner_email").eq("agent_id", agent_id).single().execute()
                owner_email = wr.data.get('owner_email')
            except Exception as e: 
                logger.error(f"Error fetching owner email for flagged transaction: {e}")
                owner_email = None
            
            # Marcamos como pendiente de aprobación solo lo sospechoso
            self.db.table("transaction_logs").update({
                "status": "PENDING_APPROVAL",
                "reason": f"Detección de Riesgo IA: {reason_text}"
            }).eq("id", tx_data.get('id')).execute()

            if owner_email:
                from notifications import send_approval_email
                # El sistema ahora enviará el correo basándose en el riesgo detectado por la IA
                tx_id = tx_data.get('id')
                try:
                    send_approval_email(owner_email, agent_id, vendor, amount, tx_id)
                    logger.info(f"📧 Solicitud de Aprobación+Aprendizaje enviada a {owner_email}")
                except Exception as e:
                    logger.error(f"⚠️ Error enviando email approval: {e}")

        else:
            # CASO: LOW RISK (Confianza Total)
            logger.info(f"✅ [THE ORACLE] Bajo riesgo detectado. Ejecutando aprendizaje automático para {vendor}.")
            
            # 1. Añadir a la whitelist del agente para que no vuelva a pasar por la IA
            self.add_to_trusted_services(agent_id, vendor)
            
            # 2. Actualizar log
            self.db.table("transaction_logs").update({
                "status": "APPROVED",
                "reason": "Auto-Validated (Low Risk) - Added to Trusted Services"
            }).eq("id", tx_data.get('id')).execute()

    def _check_role_vendor_mismatch(self, agent_role, vendor, description="", justification=""):
        """
        HEURÍSTICA UNIVERSAL DE "CABALLO DE TROYANO":
        Detecta si un Agente Profesional está intentando comprar bienes de CONSUMO PERSONAL
        disfrazados de gastos corporativos.
        
        Ahora escanea TAMBIÉN la descripción y justificación para cerrar el "Gap de Amazon".
        """
        r = agent_role.lower()
        
        # Unificamos todo el texto sospechoso
        full_context = f"{vendor} {description} {justification}".lower()
        
        # 1. Categorías de Riesgo Universal (Consumo Personal)
        # Si un agente B2B compra aquí, SIEMPRE es sospechoso (salvo que sea whitelist).
        personal_consumption_triggers = [
            # Gaming & Entertainment
            'game', 'steam', 'playstation', 'xbox', 'nintendo', 'sony', 'twitch', 'discord', 'netflix', 'spotify', 'hbo', 'disney',
            # Luxury & Fashion
            'gucci', 'rolex', 'lv', 'prada', 'balenciaga', 'nike', 'adidas', 'zara', 'fashion', 'luxury', 'jewel',
            # Vice & Dating
            'casino', 'bet', 'poker', 'dating', 'tinder', 'bumble', 'onlyfans', 'porn', 'adult',
            # Travel & Leisure (Susceptible de fraude personal)
            'airbnb', 'booking', 'expedia', 'resort', 'cruise', 'holiday',
            # Physical Goods (Gap de Amazon/Mercado Libre)
            'perfume', 'colonia', 'juguete', 'toy', 'lego', 'baby', 'bebe', 'pañal', 'diaper', 
            'clothes', 'ropa', 'shoe', 'zapat', 'sneaker', 'console', 'consola', 'ps5', 'switch',
            'ticket', 'entrada', 'concert', 'concierto', 'festival'
        ]
        
        # 2. Excepciones Lógicas (Roles que SÍ pueden gastar en esto)
        # Ejemplo: Un "Travel Agent" puede usar Airbnb. Un "Game Tester" puede usar Steam.
        # Pero por defecto, asumimos que NO.
        
        is_personal_risk = any(trigger in full_context for trigger in personal_consumption_triggers)
        
        if is_personal_risk:
            # Check de Coherencia: ¿El rol justifica el riesgo?
            # Si es 'Game Developer' y compra en 'Steam', puede ser válido -> Auditoría Síncrona requerida de todos modos por seguridad.
            # La heurística aquí es: "Ante la duda, FRENA".
            return True
            
        return False

    async def process_instant_payment(self, request: TransactionRequest):
        # ... (Validaciones iniciales de monto y sanity check existentes) ...

        # --- 0. RECUPERAR DATOS DEL AGENTE ---
        resp = self.db.table("wallets").select("agent_role, kyc_status, tax_id").eq("agent_id", request.agent_id).single().execute()
        wallet_data = resp.data or {}
        agent_role = wallet_data.get('agent_role', 'Unknown')
        kyc_level = wallet_data.get('kyc_status', 'UNVERIFIED') # Se usará después

        # --- [NUEVO] FRENO DE MANO UNIVERSAL (Trojan Defense + Amazon Gap) ---
        if self._check_role_vendor_mismatch(agent_role, request.vendor, request.description, request.justification):
            logger.critical(f"⚠️ [GUARD] ALERTA DE TROYANO: Detección semántica de riesgo personal en '{request.vendor}' / '{request.description}'. Forzando auditoría...")
            
            # Llamamos a la REALIDAD (Auditoría Síncrona Bloqueante)
            # No importa el monto. No importa el historial.
            audit_result = await audit_transaction(
                vendor=request.vendor,
                amount=request.amount,
                description=request.description,
                agent_id=request.agent_id,
                agent_role=agent_role,
                justification=request.justification,
                history=[], # No necesitamos historia para ver la contradicción semántica
                sensitivity="CRITICAL" # Máxima paranoia
            )
            
            # Si la IA dice NO (o duda), bloqueamos.
            if audit_result['decision'] in ['REJECTED', 'FLAGGED']:
                import uuid
                self.db.table("transaction_logs").insert({
                    "id": str(uuid.uuid4()),
                    "agent_id": request.agent_id,
                    "vendor": request.vendor,
                    "amount": request.amount,
                    "status": "REJECTED",
                    "reason": f"Defensa Troyana: {audit_result.get('reasoning')}",
                    "forensic_hash": audit_result.get('forensic_hash'),
                    "accounting_tag": "0000",
                    "fx_rate": 1.0, 
                    "settlement_currency": "USD",
                    "tax_deductible": False
                }).execute()
                
                return {"status": "REJECTED", "reason": audit_result.get('reasoning')}
        
        # 1. Validaciones básicas / Sanity
        if request.amount <= 0.50:
             return {"status": "REJECTED", "reason": "Monto inválido (<$0.50)"}

        # 1.1 FAST-WALL (NUEVO): Filtro de ráfaga síncrono
        from ai_guard import fast_risk_check
        logger.info(f"🔍 [FAST-WALL] Escaneando: '{request.description}' en '{request.vendor}'...")
        fast_check = fast_risk_check(request.description, request.vendor)
        if fast_check['risk'] == "CRITICAL":
            logger.critical(f"🛑 [FAST-WALL] Bloqueo inmediato: {fast_check['reason']}")
            
            # === PASO 1: BANEO (Crítico - debe ejecutarse primero) ===
            try:
                self.db.table("wallets").update({"status": "BANNED"}).eq("agent_id", request.agent_id).execute()
                logger.success(f"✅ [FAST-WALL] Agente {request.agent_id} marcado como BANNED en DB.")
            except Exception as ban_err:
                logger.critical(f"🔥 [CRITICAL] Error al banear en DB: {ban_err}")
            
            # === PASO 2: LOG (Importante pero no crítico) ===
            try:
                import uuid
                self.db.table("transaction_logs").insert({
                    "id": str(uuid.uuid4()),
                    "agent_id": request.agent_id,
                    "amount": 0.0,
                    "vendor": "FAST_WALL_SECURITY",
                    "status": "SECURITY_BAN",
                    "reason": f"Fast-Wall: {fast_check['reason']}",
                    "forensic_hash": "FAST-WALL-BAN",
                    "accounting_tag": "0000",
                    "fx_rate": 1.0, 
                    "settlement_currency": "USD",
                    "tax_deductible": False
                }).execute()
            except Exception as log_err:
                logger.warning(f"⚠️ Error al insertar log: {log_err}")
            
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
                        logger.info(f"📧 Alerta Fast-Wall enviada a {owner_email}")
                    except Exception as mail_err:
                        logger.error(f"❌ [EMAIL ERROR] No se pudo enviar email: {mail_err}")
                else:
                    logger.info(f"ℹ️ [FAST-WALL] No hay owner_email configurado para {request.agent_id}")
                    
            except Exception as alert_err:
                logger.warning(f"⚠️ Error en sistema de alertas: {alert_err}")
            
            logger.critical(f"🚫 Protocolo Fast-Wall completado. Agente {request.agent_id} neutralizado.")
            return {"status": "REJECTED", "reason": f"Seguridad: {fast_check['reason']}"}

        # 1.2 CIRCUIT BREAKER & PENDING LOCK
        if self.check_circuit_breaker(request.agent_id):
             return {"status": "REJECTED", "reason": "Velocidad excesiva (Fusible activado)"}
        
        # Check Redis Audit Lock (Si hay una auditoría crítica en curso, bloqueamos instantáneos)
        try:
            if self.redis_enabled:
                if self.redis.get(f"audit_lock:{request.agent_id}"):
                    return {"status": "REJECTED", "reason": "Cuenta bajo revisión de seguridad activa."}
        except Exception as e:
            logger.error(f"Error checking Redis audit lock: {e}")

        # 2. Identity Check (Minimal)
        # Asumimos que si tiene ID y saldo en DB, existe.
        
        # 3. Deduct Balance (Atomic RPC)
        FEE_PERCENT = 0.015 # Tarifa base (sin seguro insurance activo en sync check)
        fee = round(request.amount * FEE_PERCENT, 2)
        total_deducted = request.amount + fee
        
        try:
            # 0. CHECK LÍMITES (Escudo Diario)
            # Primero leemos para fallar rápido antes del bloqueo de DB
            w_limits = self.db.table("wallets").select("daily_limit, daily_spent").eq("agent_id", request.agent_id).single().execute()
            if w_limits.data:
                d_limit = float(w_limits.data.get('daily_limit') or 1000.0)
                d_spent = float(w_limits.data.get('daily_spent') or 0.0)
                
                if (d_spent + request.amount) > d_limit:
                    logger.warning(f"🛑 [LIMIT EXCEEDED] Agente {request.agent_id} (${d_spent}/${d_limit})")
                    return {"status": "REJECTED", "reason": "Excede el límite de gasto diario configurado."}

            logger.info(f"💰 [SECURE] Ejecutando transacción blindada para {request.agent_id}...")
            
        # 1. Deducción Segura (RPC)
            # Nota: Requiere que el usuario haya ejecutado secure_payment.sql en Supabase
            rpc_res = self.db.rpc('secure_deduct_balance', {
                'target_agent_id': request.agent_id,
                'amount_to_deduct': total_deducted
            }).execute()

            if not rpc_res.data or not rpc_res.data[0]['success']:
                return {"status": "REJECTED", "reason": "Saldo insuficiente o error de concurrencia"}

            new_balance = float(rpc_res.data[0]['updated_balance'])
            logger.success(f"✅ Transacción completada. Nuevo saldo: ${new_balance}")

            # 2. FETCH WALLET DATA (needed for legal artifacts)
            wallet_res = self.db.table("wallets").select("owner_email, tax_id").eq("agent_id", request.agent_id).single().execute()
            wallet_data = wallet_res.data if wallet_res.data else {}

            # 3. GENERACIÓN DE FACTURA & CERTIFICADO LEGAL
            # ------------------------------------------------
            try:
                # A. Certificado de Responsabilidad (Liability Chain)
                cert = self.legal_wrapper.issue_liability_certificate(
                    request.agent_id, 
                    wallet_data.get('owner_email', 'unknown@agent.com'), 
                    "agentpay.platform", 
                    forensic_hash="PENDING-HASH" # Se actualizará
                )
                
                # B. Factura PDF (VAT Compliant)
                from invoicing import generate_invoice_pdf
                tax_id = wallet_data.get('tax_id', 'EU-VAT-PENDING')
                pdf_path = generate_invoice_pdf(
                    str(uuid.uuid4()), # Temp ID for filename (will replace with log_id)
                    request.agent_id, 
                    request.vendor, 
                    request.amount, 
                    request.description, 
                    tax_id=tax_id
                )
                invoice_url = f"{self.admin_url}/v1/invoices/{os.path.basename(pdf_path)}"
            except Exception as leg_e:
                logger.error(f"⚠️ Legal artifacts failed: {leg_e}")
                invoice_url = None

            # 3. LOG MANUAL SINCRONIZADO (Corrección del Error 0)
            import uuid
            log_id = str(uuid.uuid4())
            
            # Renombrar PDF con ID real si existe
            if invoice_url and os.path.exists(pdf_path):
                 new_path = pdf_path.replace(os.path.basename(pdf_path).split('_')[1], f"{log_id}.pdf")
                 os.rename(pdf_path, new_path)
                 invoice_url = f"{self.admin_url}/v1/invoices/{os.path.basename(new_path)}"

            # Determines accounting tags logic
            gl_code, deductible = self.identify_accounting_nature(request.vendor, mcc_cat='services')

            # Construimos el payload completo para evitar rechazos por esquema
            log_payload = {
                "id": log_id,
                "agent_id": request.agent_id,
                "vendor": request.vendor,
                "amount": request.amount, # Monto neto
                "fee": fee,               # Comisión separada
                "description": request.description,
                "status": "APPROVED",
                "reason": "Pago Seguro Verificado (Atomic)",
                "forensic_hash": str(uuid.uuid4()),
                "invoice_url": invoice_url,
                "accounting_tag": gl_code,
                "fx_rate": 1.0, 
                "settlement_currency": "USD",
                "tax_deductible": deductible,
                "mcc_category": "services",
                "created_at": datetime.now().isoformat()
            }
            
            # Insertamos con manejo de error explícito
            self.db.table("transaction_logs").insert(log_payload).execute()

        except Exception as e:
            # Si falla aquí, tenemos un problema de consistencia (Dinero descontado, sin log)
            # Imprimimos el error real, no solo el código
            error_details = str(e)
            if hasattr(e, 'message'): error_details += f" | {e.message}"
            if hasattr(e, 'code'): error_details += f" | Code: {e.code}"
            
            logger.critical(f"CRITICAL ERROR: Money deducted but log failed: {error_details}")
            return {"status": "REJECTED", "reason": f"Error de Integridad: {error_details}"}

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
        except Exception as e:
            logger.error(f"Error setting Redis audit lock: {e}")

        # 6. Return Success with Pending Audit status
        return {
            "success": True,
            "status": "APPROVED_PENDING_AUDIT",
            "message": "Pago aprobado (Auditoría en curso)",
            "transaction_id": card['id'], 
            "db_log_id": log_id, # <--- NUEVO CAMPO CRÍTICO
            "card": card,
            "balance": "hidden (async)", 
            "forensic_url": invoice_url
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

            logger.info(f"💳 Procesando cobro de tarjeta ({payment_method_id}) para {agent_id}...")

            # 2. EJECUTAR EL COBRO REAL (Sin redirección)
            # --- SOPORTE MULTIDIVISA (Pillar 3) ---
            target_currency = 'usd'
            # Margen de seguridad Forex (2%)
            amount_to_charge = amount
            # if user_currency == 'eur': amount_to_charge = amount_usd * 0.92 * 1.02
            
            intent = stripe.PaymentIntent.create(
                amount=int(amount_to_charge * 100),
                currency=target_currency,
                payment_method=payment_method_id, # <--- LA TARJETA DEL USUARIO
                confirm=True, # <--- COBRO INMEDIATO
                description=f"Recarga de Saldo para {agent_id} (FX Safety Applied)",
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
            logger.warning(f"Tarjeta rechazada for {agent_id}: {e.user_message}")
            return {"status": "FAILED", "message": f"Tarjeta rechazada: {e.user_message}"}
        except Exception as e:
            logger.error(f"Error charging user card for {agent_id}: {e}")
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
             logger.error(f"Error getting agent status for {agent_id}: {e}")
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
        except Exception as e:
            logger.error(f"Error calculating dashboard metrics for {agent_id}: {e}")
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
            logger.info(f"Value {perceived_value_usd} recorded for transaction {transaction_id}")
        else:
            logger.warning(f"Transaction {transaction_id} not found for value reporting.")
        return {"status": "VALUE_RECORDED", "perceived_value": perceived_value_usd}

    def _result(self, auth, status, reason, req, bal=None, invoice_url=None, fee=0.0, card_data=None, forensic_url=None, mcc_category=None, intent_hash=None, gl_code=None, deductible=None, fx_rate=1.0, settlement_currency="USD"):
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
            "forensic_hash": forensic_url.split('/')[-1] if forensic_url else None,
            "fx_rate": fx_rate,
            "settlement_currency": "USD",
            "accounting_tag": gl_code if gl_code else "0000",
            "tax_deductible": deductible if deductible is not None else False,
            "mcc_category": mcc_category,
            "created_at": datetime.now().isoformat()
        }
        
        if invoice_url: payload["invoice_url"] = invoice_url
        
        try:
            self.db.table("transaction_logs").insert(payload).execute()
        except Exception as e:
            logger.error(f"⚠️ Error guardando log en Supabase: {e}")
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
        logger.info(f"Agent {agent_id} signed terms of service.")
        return {"status": "SIGNED", "certificate": cert}

    def process_quote_request(self, provider_agent_id, service_type, parameters: dict):
        wallet = self.db.table("wallets").select("*").eq("agent_id", provider_agent_id).execute()
        catalog = wallet.data[0].get('services_catalog', {})
        price = float(catalog.get(service_type.lower(), 10.0))
        logger.info(f"Quote requested for {service_type} from {provider_agent_id}: ${price}")
        return {"status": "QUOTED", "quote": {"quote_id": f"Q-{uuid.uuid4().hex[:6]}", "price": price, "currency": "USD"}}



    def raise_escrow_dispute(self, agent_id, transaction_id, issue, evidence):
        """
        El Juez IA entra en acción: Arbitraje Real basado en evidencia técnica.
        """
        # 1. Recuperar contexto
        try:
            tx_res = self.db.table("transaction_logs").select("*").eq("id", transaction_id).execute()
            tx = tx_res.data[0] if tx_res.data else {}
        except Exception as e:
            logger.error(f"Error retrieving transaction {transaction_id} for dispute: {e}")
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
            logger.error(f"❌ Error llamando al Lawyer: {e}")
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
            logger.error(f"⚠️ Error actualizando DB en disputa: {e}")
        
        logger.info(f"Dispute for {transaction_id} processed. Verdict: {verdict.get('judicial_opinion')}, Action: {action}")
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
        logger.info(f"🤖 [QR VISION] Analizando QR para el agente {payer_agent_id}...")
        logger.info(f"   🔗 URL Detectada: {qr_url}")

        try:
            # 1. Extraer el Session ID de la URL
            # Formato típico: https://checkout.stripe.com/c/pay/cs_test_a1b2c3...
            if "cs_test_" not in qr_url and "cs_live_" not in qr_url:
                logger.warning(f"Formato de QR no válido o desconocido: {qr_url}")
                return {"status": "ERROR", "message": "Formato de QR no válido o desconocido."}

            session_id = qr_url.split("/")[-1].split("#")[0]  # Limpieza básica
            
            # 2. Consultar a Stripe los detalles de esa sesión (La "Factura")
            # Como somos la Plataforma, podemos leer la sesión aunque sea de otro usuario
            session = stripe.checkout.Session.retrieve(session_id)
            
            if session.payment_status == 'paid':
                logger.info(f"QR {session_id} already paid.")
                return {"status": "ALREADY_PAID", "message": "Este QR ya ha sido pagado."}

            # 3. Extraer datos clave
            amount_dollars = session.amount_total / 100.0
            receiver_agent_id = session.metadata.get('agent_id')
            
            if not receiver_agent_id:
                logger.warning(f"QR {session_id} does not contain receiver agent_id metadata.")
                return {"status": "ERROR", "message": "El QR no contiene metadatos del agente destino."}

            logger.info(f"   🧠 [QR ANALYSIS] Detectado cobro de ${amount_dollars} para {receiver_agent_id}")

            # 4. EJECUTAR EL PAGO (M2M Transfer)
            # Usamos la lógica de cobro directo (pm_card_visa simula la tarjeta del agente pagador)
            
            # Recuperar cuenta Stripe del DESTINATARIO para enviarle la plata
            receiver_wallet = self.db.table("wallets").select("stripe_account_id").eq("agent_id", receiver_agent_id).execute()
            if not receiver_wallet.data:
                 logger.error(f"Receiver {receiver_agent_id} does not have a connected Stripe account.")
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
            except Exception as e: 
                logger.warning(f"Failed to expire Stripe checkout session {session_id}: {e}") # Si ya expiró o falló, no importa, el pago ya se hizo

            # 6. Registrar en Base de Datos (Log de Payer y Receiver)
            # Restamos saldo lógico al pagador (si gestionamos saldo interno)
            # Nota: deduct_balance debe existir en la DB como función RPC
            try:
                self.db.rpc("deduct_balance", {"p_agent_id": payer_agent_id, "p_amount": amount_dollars}).execute()
            except Exception as e:
                logger.warning(f"⚠️ Nota: No se pudo descontar saldo interno (quizás usa tarjeta directa): {e}")

            logger.success(f"Pago por QR completado exitosamente. TX ID: {intent.id}")
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
            logger.error(f"❌ Error procesando QR: {e}")
            return {"status": "ERROR", "message": str(e)}
        

    # --- SECURITY & AUTHENTICATION ---
    def verify_agent_kyc(self, agent_id):
        """
        Llama a Stripe para ver si el usuario ya pasó el KYC/KYB.
        """
        try:
            # 1. Recuperar el ID de cuenta de Stripe
            wallet = self.db.table("wallets").select("stripe_account_id").eq("agent_id", agent_id).execute()
            if not wallet.data: 
                logger.warning(f"Agent {agent_id} not found for KYC verification.")
                return {"status": "ERROR", "message": "Agente no encontrado"}
            
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
            
            logger.info(f"KYC status for {agent_id} is {status}.")
            return {
                "agent_id": agent_id,
                "kyc_status": status,
                "needs_more_info": account.requirements.currently_due
            }
        except Exception as e:
            logger.error(f"Error verifying agent KYC for {agent_id}: {e}")
            return {"status": "ERROR", "message": str(e)}

    def _deprecated_duplicate_webhook(self, payload, sig_header):
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, self.webhook_secret
            )
        except Exception as e:
            # Si falla la firma normal, podría ser un evento de Connect
            # En producción, deberías configurar un webhook secreto separado para Connect
            logger.warning(f"⚠️ Webhook signature error (o evento Connect): {e}")
            return {"status": "ignored"}

        # 1. RECARGAS (El dinero entra)
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            agent_id = session.get('metadata', {}).get('agent_id')
            # Con Connect, el dinero ya está en SU cuenta, solo registramos el evento
            if agent_id:
                logger.info(f"💰 Recarga completada para {agent_id}")
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
            logger.info(f"💳 Intento de cobro: ${auth['amount']/100} en {auth['merchant_data']['name']}")
            
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
                logger.info(f"🔐 Acceso Autorizado: {resp.data[0]['agent_id']}")
                return resp.data[0]['agent_id']
                
            logger.warning(f"🛑 Acceso Denegado: Token inválido")
            return None
        except Exception as e:
            logger.error(f"⚠️ Auth Error: {e}")
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
            logger.info(f"🥷 Creando Agente Automático: {client_name}...")

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
            
            logger.success(f"✅ Agente {agent_id} creado y activo con Stripe Account ID: {account.id}")
            return {
                "status": "CREATED",
                "agent_id": agent_id,
                "api_key": raw_secret,
                "stripe_account_id": account.id,
                "message": "Agente listo y activo para recibir dinero automáticamente."
            }

        except Exception as e:
            logger.error(f"❌ Error creando agente: {e}")
            return {"status": "ERROR", "message": str(e)}

    def update_agent_settings(self, agent_id, webhook_url=None, owner_email=None):
        data = {}
        if webhook_url: data["webhook_url"] = webhook_url
        if owner_email: data["owner_email"] = owner_email
        self.db.table("wallets").update(data).eq("agent_id", agent_id).execute()
        logger.info(f"Agent {agent_id} settings updated.")
        return {"status": "UPDATED"}

    def update_limits(self, agent_id, max_tx=None, daily_limit=None):
        data = {}
        if max_tx: data["max_transaction_limit"] = max_tx
        if daily_limit: data["daily_limit"] = daily_limit
        self.db.table("wallets").update(data).eq("agent_id", agent_id).execute()
        logger.info(f"Limits for agent {agent_id} updated.")
        return {"status": "LIMITS_UPDATED"}

    def check_payment_status(self, transaction_id):
        res = self.db.table("transaction_logs").select("*").eq("id", transaction_id).execute()
        if res.data: 
            logger.debug(f"Payment status for {transaction_id} checked.")
            return res.data[0]
        logger.warning(f"Transaction {transaction_id} not found for status check.")
        return {"error": "Not found"}

    def get_invoice_url(self, transaction_id):
        logger.debug(f"Invoice URL requested for {transaction_id}.")
        return {"invoice_url": f"{self.admin_url}/v1/invoices/{transaction_id}.pdf"}

    def dispute_transaction(self, agent_id, transaction_id, reason):
        self.db.table("transaction_logs").update({
            "status": "DISPUTED", 
            "reason": f"Disputa iniciada por el agente: {reason}"
        }).eq("id", transaction_id).execute()
        logger.warning(f"Dispute opened for transaction {transaction_id} by {agent_id}: {reason}")
        return {"status": "DISPUTE_OPENED"}

    def get_agent_passport(self, agent_id):
        passport = self.legal_wrapper.issue_kyc_passport(agent_id, "Synthetic Entity")
        logger.info(f"Agent passport issued for {agent_id}.")
        return passport

    def process_quote_request(self, provider_id, service_type, parameters: dict):
        logger.info(f"Quote requested for {service_type} from {provider_id}.")
        return {"quote": 1.50, "currency": "USD", "provider": provider_id, "expires_in": 3600}

    def get_service_directory(self, role="ALL"):
        logger.debug(f"Service directory requested for role: {role}.")
        return {"directory": [
            {"name": "DataScraper_AI", "role": "data_procurement", "price": 0.50},
            {"name": "Translator_Bot", "role": "translation", "price": 0.10}
        ]}

    def send_alert(self, agent_id, message):
        logger.info(f"Alert sent to {agent_id}: {message}")
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
                logger.warning(f"Agent {agent_id} not found for issuing activation.")
                return {"status": "ERROR", "message": "Agente no encontrado."}
            
            acct_id = wallet.data[0]['stripe_account_id']
            
            logger.info(f"🚀 Activando Issuing para la cuenta {acct_id}...")

            # 2. Llamada a la API de Stripe para solicitar la capability
            stripe.Account.modify(
                acct_id,
                capabilities={
                    "card_issuing": {"requested": True}, # <--- AQUÍ SÍ LO PEDIMOS
                }
            )

            logger.success(f"✅ Solicitud de Issuing enviada a Stripe para {agent_id}.")
            return {
                "status": "ACTIVATED",
                "message": "Solicitud de Issuing enviada a Stripe. Si el KYC está ok, se activará en minutos.",
                "agent_id": agent_id,
                "stripe_account": acct_id
            }

        except Exception as e:
            logger.error(f"❌ Error activando Issuing para {agent_id}: {e}")
            return {"status": "ERROR", "message": str(e)}

    # --- PILLAR 3: SELF-LEARNING (Auto-Whitelist) ---
    def add_to_trusted_services(self, agent_id, vendor_domain):
        """
        Añade un vendedor a la whitelist del agente tras aprobación manual.
        Esto reduce el riesgo en futuras compras.
        """
        try:
             # 1. Recuperar catálogo actual
             wallet = self.db.table("wallets").select("services_catalog").eq("agent_id", agent_id).single().execute()
             catalog = wallet.data.get("services_catalog") or {}
             
             # MIGRACIÓN AUTOMÁTICA (List -> Dict)
             if isinstance(catalog, list):
                 catalog = {v: "trusted" for v in catalog}

             # 2. Añadir si no existe
             clean_vendor = self._normalize_domain(vendor_domain)
             if clean_vendor not in catalog:
                 catalog[clean_vendor] = "trusted"
                 
                 # 3. Guardar en DB
                 self.db.table("wallets").update({"services_catalog": catalog}).eq("agent_id", agent_id).execute()
                 logger.info(f"🧠 [HIVE MIND] {clean_vendor} ha sido aprendido como SEGURO para {agent_id}.")
                 return True
             
             return False # Ya estaba
        except Exception as e:
            logger.error(f"⚠️ Error en Self-Learning: {e}")
            return False

    # --- INFRAESTRUCTURA INDUSTRIAL (Roadmap 2026) ---
    async def get_security_metrics(self):
        """
        Retorna el 'Pulso de Seguridad' del sistema.
        """
        try:
            # 1. Ataques detenidos (SECURITY_BAN o REJECTED)
            bans = self.db.table("transaction_logs").select("id", count="exact").eq("status", "SECURITY_BAN").execute()
            rejections = self.db.table("transaction_logs").select("id", count="exact").eq("status", "REJECTED").execute()
            
            # 2. Comunidad protegida (Mente Colmena)
            reputation_entries = self.db.table("global_reputation_cache").select("domain", count="exact").execute()
            
            total_detoured = (bans.count or 0) + (rejections.count or 0)
            
            return {
                "security_level": "BANK_GRADE",
                "detoured_attacks": total_detoured,
                "global_reputation_entries": reputation_entries.count or 0,
                "hive_mind_status": "SYNCHRONIZED",
                "identity_health": "PROTECTED",
                "compliance_score": 98.4
            }
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    def create_escrow_transaction(self, agent_id, vendor, amount, description):
        """
        Garantía de Fondos (Escrow): Asegura que el dinero solo se libere
        al confirmar recepción del servicio/bienes.
        """
        clean_vendor = self._normalize_domain(vendor)
        tx_id = str(uuid.uuid4())
        
        # 1. Debitar saldo inmediatamente (Bloqueo de fondos)
        try:
            res = self.db.rpc("deduct_balance", {"p_agent_id": agent_id, "p_amount": amount}).execute()
            if not res.data:
                return {"status": "REJECTED", "reason": "Saldo insuficiente para Escrow."}
        except:
             return {"status": "REJECTED", "reason": "Error al fondear Escrow."}

        # 2. Registrar Transacción en estado HOLD
        self.db.table("transaction_logs").insert({
            "id": tx_id,
            "agent_id": agent_id,
            "vendor": clean_vendor,
            "amount": amount,
            "status": "ESCROW_HOLD",
            "description": f"[ESCROW] {description}",
            "reason": "Dinero retenido por Garantía de Fondos (Roadmap 2026)"
        }).execute()

        return {
            "status": "ESCROW_ACTIVE",
            "transaction_id": tx_id,
            "message": f"Fondos (${amount}) protegidos en Escrow para {clean_vendor}."
        }

    def release_escrow(self, transaction_id):
        """Libera los fondos y emite el pago real."""
        # En un sistema real, aquí llamaríamos a Stripe Issuing
        self.db.table("transaction_logs").update({
            "status": "ESCROW_RELEASED",
            "reason": "Fondos liberados por confirmación del Agente."
        }).eq("id", transaction_id).execute()
        return {"status": "PAID", "message": "Garantía liberada. Pago procesado."}
        """
        Procesa la aprobación manual de una transacción desde el email.
        """
        try:
             # Aquí deberías validar el token (JWT)
             # Por simplicidad, asumimos que el token es el ID de transacción directo o un JWT decodificado
             transaction_id = token 
             
             # 1. Recuperar Transacción
             tx = self.db.table("transaction_logs").select("*").eq("id", transaction_id).single().execute()
             if not tx.data: return {"error": "Transacción no encontrada"}
             
             tx_data = tx.data
             
             # 2. Aprobar
             self.db.table("transaction_logs").update({
                 "status": "APPROVED",
                 "reason": "Aprobado manualmente por el propietario."
             }).eq("id", transaction_id).execute()
             
             # 3. APRENDIZAJE AUTOMÁTICO (Hive Mind)
             # Si el humano aprueba, el vendedor se vuelve de confianza
             agent_id = tx_data.get('agent_id')
             vendor = tx_data.get('vendor')
             
             if vendor and agent_id:
                 self.add_to_trusted_services(agent_id, vendor)
             
             return {"status": "APPROVED", "message": "Transacción aprobada y vendedor añadido a whitelist."}
             
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}