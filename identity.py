import time
import os
import uuid
import random
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
                print(f"⚠️ Error persistiendo identidad: {e}")

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
            print(f"   📬 [IDENTITY] Email encontrado: {last_email.get('subject')}")

            # 3. Usar la IA para leerlo
            extracted_code = self.parse_inbound_email({
                "subject": last_email.get('subject', ''),
                "body": last_email.get('body_text', '')
            })
            
            return extracted_code

        except Exception as e:
            print(f"❌ Error Checking Inbox: {e}")
            return f"ERROR: {str(e)}"

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
            Analiza este email y extrae ÚNICAMENTE el código de verificación (OTP) o la URL de aprobación.
            
            ASUNTO: {subject}
            CUERPO: {body}
            
            Si hay un código numérico, responde SOLO con el número.
            Si hay un enlace de aprobación (approve?token=...), responde SOLO con la URL.
            Si no hay nada, responde "NO_CODE".
            """
            
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"Error AI Extracting: {e}")
            return "AI_PARSING_ERROR"

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
            cuerpo = str(last_sms.get('body', '')) # Forzamos string
            remitente = last_sms.get('sender', 'Unknown')
            
            print(f"   📱 [SMS] Mensaje encontrado de {remitente}: {cuerpo}")

            # Reutilizamos tu lógica de extracción (IA o Regex)
            return self._extract_code_with_ai("SMS Verification", cuerpo)

        except Exception as e:
            print(f"❌ Error Checking SMS: {e}")
            return f"ERROR: {str(e)}"

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

    def generate_browser_fingerprint(self):
        """
        Genera metadatos de navegación realistas para evitar detección de bots.
        """
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
        ]
        return {
            "user_agent": random.choice(user_agents),
            "viewport": {"width": 1920, "height": 1080},
            "device_memory": 8,
            "hardware_concurrency": 4,
            "webgl_vendor": "Google Inc. (NVIDIA)",
            "renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3090 Direct3D11 vs_5_0 ps_5_0, D3D11)"
        }

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

    def recover_session(self, agent_id):
        if self.db:
            try:
                res = self.db.table("identities").select("session_blob").eq("agent_id", agent_id).execute()
                return res.data[0].get('session_blob') if res.data else None
            except: return None
        return None
