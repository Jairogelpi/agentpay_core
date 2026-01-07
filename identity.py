import time
import os
import uuid
import random
import json
import boto3   # <--- NUEVO
import base64  # <--- NUEVO
from cryptography.fernet import Fernet # <--- NUEVO
from loguru import logger

from openai import OpenAI

# Intentamos inicializar el cliente de OpenAI
try:
    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
except:
    client = None

class IdentityManager:
    """
    Gestor Universal de Identidades.
    Genera emails temporales y extrae códigos de verificación automáticamente.
    """
    
    def __init__(self, db_client=None):
        self.db = db_client
        self.domain = "agentpay.it.com" # Tu dominio
        
        # --- INICIO BLOQUE KMS (CIFRADO) ---
        try:
            self.kms = boto3.client(
                'kms',
                region_name=os.getenv("AWS_REGION", "eu-north-1"),
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
            )
            # USAMOS LA LLAVE DE CIFRADO (SIMÉTRICA)
            self.encryption_key_id = os.getenv("KMS_ENCRYPTION_KEY_ID")
            
            if self.encryption_key_id:
                logger.info("✅ Identity Manager conectado a AWS KMS (Cifrado Militar)")
            else:
                logger.warning("⚠️ KMS_ENCRYPTION_KEY_ID no configurado. Las sesiones no estarán cifradas.")
                
        except Exception as e:
            logger.warning(f"⚠️ Error conectando KMS Cifrado: {e}")
            self.kms = None
        # --- FIN BLOQUE KMS ---

    def create_identity(self, agent_id, needs_phone=False):
        return self.create_certified_identity(agent_id)

    def create_certified_identity(self, agent_id, provider="AgentPay Secure Mail"):
        clean_id = agent_id.replace("sk_", "").replace("_", "")[:12]
        email_address = f"agent-{clean_id}@{self.domain}"
        
        identity_data = {
            "identity_id": f"cert_{clean_id}",
            "agent_id": agent_id,
            "email": email_address,
            "domain": self.domain,
            "type": "CERTIFIED",
            "provider": provider
        }

        if self.db:
            try:
                self.db.table("identities").upsert({
                    "agent_id": agent_id,
                    "identity_id": identity_data['identity_id'],
                    "email": email_address,
                    "provider": provider,
                    "status": "active_certified"
                }).execute()
            except Exception as e:
                logger.error(f"⚠️ Error persistiendo identidad: {e}")

        return identity_data

    # --- 🛠️ ESTA ES LA FUNCIÓN QUE FALTABA 🛠️ ---
    def check_inbox(self, identity_id):
        """
        Consulta la base de datos 'inbound_emails' para ver si ha llegado algo.
        Usa GPT para extraer el código OTP si hay un email nuevo.
        """
        if not self.db:
            return "DB_NOT_CONNECTED"

        try:
            # 1. Averiguar el agent_id real detrás de este identity_id
            target_agent_id = identity_id
            
            # Si el ID empieza por cert_, buscamos el mapping en la tabla identities
            if identity_id.startswith("cert_"):
                lookup = self.db.table("identities").select("agent_id").eq("identity_id", identity_id).execute()
                if lookup.data:
                    target_agent_id = lookup.data[0]['agent_id']
            
            # 2. Buscar el último email recibido para ese agente
            # Ordenamos por fecha descendente (created_at) y cogemos 1
            response = self.db.table("inbound_emails").select("*").eq("agent_id", target_agent_id).order("created_at", desc=True).limit(1).execute()
            
            if not response.data:
                return "NO_EMAILS" # Aún no ha llegado nada
            
            last_email = response.data[0]
            logger.debug(f"   📬 [IDENTITY] Email encontrado: {last_email.get('subject')}")

            # 3. Usar la IA para leerlo
            analysis = self.parse_inbound_email({
                "subject": last_email.get('subject', ''),
                "body": last_email.get('body_text', '')
            })
            
            # Si se solicita solo el código (legacy), devolvemos el valor
            if isinstance(analysis, dict):
                return analysis.get("value", "") # Return extracted value directly to keep tools simple
            
            return analysis

        except Exception as e:
            logger.error(f"❌ Error Checking Inbox: {e}")
            return f"ERROR: {str(e)}"

    def _encrypt_data(self, plain_text: str):
        """Cifrado de Sobre (Envelope Encryption)."""
        if not self.kms or not self.encryption_key_id:
            return {"blob": plain_text, "envelope": None} # Fallback inseguro

        # 1. Pedir a AWS una llave desechable para ESTA sesión
        response = self.kms.generate_data_key(
            KeyId=self.encryption_key_id,
            KeySpec='AES_256'
        )
        
        # Llave en plano (vive solo milisegundos en RAM)
        plaintext_key = base64.b64encode(response['Plaintext'])
        # Llave cifrada (para guardar en DB)
        encrypted_key_blob = response['CiphertextBlob']
        
        # 2. Cifrar los datos con la llave desechable
        f = Fernet(plaintext_key)
        encrypted_data = f.encrypt(plain_text.encode())
        
        return {
            "blob": encrypted_data.decode('utf-8'),
            "envelope": base64.b64encode(encrypted_key_blob).decode('utf-8')
        }

    def save_session_state(self, agent_id, cookies_dict):
        """Guarda las cookies cifradas en la base de datos."""
        if not self.db: return False
        
        json_data = json.dumps(cookies_dict)
        
        # CIFRAR ANTES DE GUARDAR
        secure_packet = self._encrypt_data(json_data)
        
        try:
            self.db.table("identities").update({
                "session_blob": secure_packet['blob'],
                # Asegúrate de haber creado esta columna en Supabase:
                "encryption_envelope": secure_packet['envelope'], 
                "last_active": "now()"
            }).eq("agent_id", agent_id).execute()
            
            logger.info(f"🔒 Sesión guardada y cifrada para {agent_id}")
            return True
        except Exception as e:
            logger.error(f"❌ Error guardando sesión: {e}")
            return False

    def parse_inbound_email(self, email_content):
        if isinstance(email_content, dict):
            subject = email_content.get('subject', '')
            body = email_content.get('body', '') or email_content.get('text', '')
        else:
            subject = "Raw Inbound"
            body = str(email_content)

        return self._extract_code_with_ai(subject, body)

    def _extract_code_with_ai(self, subject, body):
        if not client:
            # Fallback simple sin IA
            import re
            match = re.search(r'\b\d{6}\b', body)
            return match.group(0) if match else "NO_IA_NO_CODE"
            
        try:
            prompt = f"""
            Analiza este email y extrae DATOS DE ACCIÓN.
            Prioridad:
            1. CÓDIGO DE VERIFICACIÓN (OTP) numérico (Ej: 123456).
            2. ENLACE DE FACTURA/INVOICE (PDF, JPG, Link).
            3. ENLACE DE APROBACIÓN (approve?token=...).
            
            ASUNTO: {subject}
            CUERPO: {body}
            
            Responde en JSON STRICTO:
            {{
                "type": "OTP" | "INVOICE" | "APPROVAL" | "NONE",
                "value": "el código o la url extraída",
                "confidence": 0-100
            }}
            """
            
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.0
            )
            return json.loads(response.choices[0].message.content.strip())
        except Exception as e:
            logger.error(f"Error AI Extracting: {e}")
            return {"type": "ERROR", "value": str(e)}

    # --- AÑADIR DENTRO DE class IdentityManager ---
    
    def check_sms_inbox(self):
        """
        Mira en la tabla inbound_sms si ha llegado algo nuevo.
        """
        if not self.db:
            return "DB_NOT_CONNECTED"

        try:
            # Buscamos el último SMS recibido (sin filtrar por agente para este test)
            response = self.db.table("inbound_sms").select("*").order("created_at", desc=True).limit(1).execute()
            
            if not response.data:
                return "NO_SMS"
            
            last_sms = response.data[0]
            msg_body = last_sms.get('body', "")
            remitente = last_sms.get('from_number', "")

            logger.info(f"   📱 [SMS] Mensaje encontrado de {remitente}: {msg_body}")
            
            return {
                "content": msg_body, 
                "from": remitente,
                "timestamp": last_sms['created_at'] 
            }
        except Exception as e:
            logger.error(f"❌ Error Checking SMS: {e}")
            return None

    # --- INFRAESTRUCTURA DE RED INDUSTRIAL (Pillar 1) ---
    def get_residential_proxy(self, country="US"):
        """
        Configuración para proveedores industriales como Bright Data u Oxylabs.
        Permite que el tráfico del agente salga desde una IP doméstica real.
        """
        proxy_user = os.getenv("PROXY_USER")
        proxy_pass = os.getenv("PROXY_PASS")
        # Default a endpoint común de Bright Data/Oxylabs si no hay ENV
        proxy_host = os.getenv("PROXY_HOST", "zproxy.lum-superproxy.io:22225")
        
        # Formato industrial estándar
        proxy_url = f"http://{proxy_user}-country-{country}:{proxy_pass}@{proxy_host}"
        
        return {
            "http": proxy_url, 
            "https": proxy_url
        }

    def generate_browser_fingerprint(self, agent_id):
        """
        Huella Digital Persistente: Cada agente tiene un navegador único.
        Asigna metadatos fijos para evitar que Amazon/Google detecten rotación de bots.
        """
        # 1. Intentar recuperar del DB
        if self.db:
            try:
                res = self.db.table("identities").select("browser_fingerprint").eq("agent_id", agent_id).execute()
                if res.data and res.data[0].get('browser_fingerprint'):
                    return res.data[0]['browser_fingerprint']
            except: pass

        # 2. Generar huella determinista basada en el agent_id o aleatoria estable
        seed = abs(hash(agent_id))
        resolutions = [(1920, 1080), (1440, 900), (1366, 768), (1536, 864)]
        res_choice = resolutions[seed % len(resolutions)]
        
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ]
        
        fingerprint = {
            "user_agent": user_agents[seed % len(user_agents)],
            "viewport": {"width": res_choice[0], "height": res_choice[1]},
            "device_memory": 8 if seed % 2 == 0 else 16,
            "hardware_concurrency": 4 if seed % 2 == 0 else 8,
            "webgl_vendor": "Google Inc. (NVIDIA)" if seed % 2 == 0 else "Google Inc. (Intel)",
            "renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3090)" if seed % 2 == 0 else "ANGLE (Intel, Intel(R) UHD Graphics 620)",
            "platform": "Win32" if "Windows" in user_agents[seed % len(user_agents)] else "MacIntel"
        }

        # 3. Guardar en DB para futura consistencia
        if self.db:
            try:
                self.db.table("identities").update({"browser_fingerprint": fingerprint}).eq("agent_id", agent_id).execute()
            except: pass

        return fingerprint

    # --- MEMORIA Y SESIONES ---
    def solve_captcha(self, image_url):
        return {"status": "SOLVED", "solution": "MOCK_SOLUTION_123"}
        
    def save_session(self, agent_id, cookies_blob):
        if self.db:
            try:
                self.db.table("identities").update({"session_blob": cookies_blob}).eq("agent_id", agent_id).execute()
                return True
            except: return False
        return False

    def update_session_data(self, identity_id, session_data):
        """Wrapper para actualizar sesión (llamado desde API)"""
        # Resolvimos que identity_id podría ser agent_id si no hay lookup.
        # Intentamos buscar el agent_id si empieza por "cert_"
        agent_id = identity_id
        if identity_id.startswith("cert_"):
             # Lookup agent_id
             try:
                 res = self.db.table("identities").select("agent_id").eq("identity_id", identity_id).execute()
                 if res.data: agent_id = res.data[0]['agent_id']
             except: pass
        
        return self.save_session_state(agent_id, session_data)

    def recover_session(self, agent_id):
        if self.db:
            try:
                res = self.db.table("identities").select("session_blob").eq("agent_id", agent_id).execute()
                return res.data[0].get('session_blob') if res.data else None
            except: return None
        return None

    # --- CRYPTOGRAPHIC SIGNING (ACP PROTOCOL) ---
    def sign_payload(self, agent_id: str, data_to_sign: str) -> str:
        """
        Signs a string using AWS KMS (ECC/RSA Asymmetric Key).
        Used for HTTP Message Signatures and ACP Mandates.
        """
        if not self.kms or not self.signing_key_id:
            logger.warning("⚠️ KMS Sign Key missing. Returning Mock Signature (UNSAFE FOR PROD).")
            return f"mock_sig_{abs(hash(data_to_sign))}"

        try:
            # We sign the raw bytes of the utf-8 string
            response = self.kms.sign(
                KeyId=self.signing_key_id,
                Message=data_to_sign.encode('utf-8'),
                MessageType='RAW',
                SigningAlgorithm='ECDSA_SHA_256' # Standard for ACP
            )
            
            # Return base64 encoded signature
            return base64.b64encode(response['Signature']).decode('utf-8')
            
        except Exception as e:
            logger.error(f"❌ KMS Signing Failed: {e}")
            raise e

    def get_mandate_hash(self, agent_id: str) -> str:
        """
        Returns a stable hash of the agent's identity for the protocol.
        In a real DID system, this would be the DID Document Hash.
        """
        # For our MVP, we hash the agent_id with a salt
        salt = os.getenv("MANDATE_SALT", "agentpay-v1-static-salt")
        payload = f"{agent_id}:{salt}"
        return hashlib.sha256(payload.encode()).hexdigest()

    def generate_payment_token(self, agent_id: str, amount: float, merchant_id: str, currency: str = "USD") -> dict:
        """
        [DELEGATED PAYMENT SPEC]
        Generates a SharedPaymentToken (Scoped Access Token) for the merchant.
        The merchant uses this token to capture funds via Stripe/Processor.
        """
        now = int(time.time())
        token_payload = {
            "iss": "agentpay.ai",           # Issuer
            "sub": f"did:agentpay:{agent_id}", # Subject (Buyer)
            "aud": merchant_id,             # Audience (Merchant)
            "amount": amount,               # Scoped Amount
            "currency": currency,
            "exp": now + 300,               # 5 Minute Expiry
            "iat": now,
            "jti": str(uuid.uuid4())        # Unique Token ID
        }
        
        # Serialize and Sign
        payload_str = json.dumps(token_payload)
        signature = self.sign_payload(agent_id, payload_str)
        
        return {
            "token_format": "agentpay_v1_cwt",
            "payload": token_payload,
            "signature": signature,
            "public_key_ref": f"did:agentpay:{agent_id}#primary"
        }

    def handle_inbound_email(self, payload):
        """
        [WEBHOOK] Procesa email entrante desde Brevo/SendGrid.
        El formato de entrada es normalizado (JSON).
        """
        # Extraer campos clave
        sender = payload.get("sender", "unknown")
        recipient = payload.get("recipient", "unknown")
        subject = payload.get("subject", "No Subject")
        body = payload.get("body", "")
        
        # Intentar extraer el ID del agente desde el recipiente (agent-XYZ@...)
        agent_id = None
        try:
            # agent-123456@agentpay.it.com -> 123456
            if "agent-" in recipient:
                 local_part = recipient.split("@")[0] # agent-123456 
                 # En nuestro sistema real, quizás hay un mapping en DB
                 # Por simplicidad en MVP, asumimos que podemos buscar por "cert_{clean_id}" si fuera necesario
                 # Pero guardamos el 'agent_id' directamente si podemos inferirlo o buscarlo.
        except: pass

        # Guardar en inbound_emails (Supabase)
        try:
            if self.db:
                # Primero buscamos si existe una identidad con ese email para linkearlo al agent_id real
                db_res = self.db.table("identities").select("agent_id").eq("email", recipient).execute()
                if db_res.data:
                    agent_id = db_res.data[0]['agent_id']

                self.db.table("inbound_emails").insert({
                    "agent_id": agent_id,
                    "sender": sender,
                    "recipient": recipient,
                    "subject": subject,
                    "body_text": body,
                    "received_at": "now()"
                }).execute()
                
                logger.info(f"📧 [INBOUND] Email guardado para {recipient}: {subject}")
                return {"status": "SAVED", "agent_id": agent_id}
            else:
                 logger.warning("⚠️ DB not connected for inbound email")
                 return {"status": "ERROR_DB"}
        except Exception as e:
            logger.error(f"❌ Error saving inbound email: {e}")
            return {"status": "ERROR", "message": str(e)}
