import time
import os
import uuid
import random
from openai import OpenAI

# Usamos la configuración de cliente que ya tengamos, o creamos uno nuevo
# Dependiendo de tu estructura, podrías importar 'client' de ai_guard.py
# Aquí lo instancio fresco para asegurar que funcione aislado.

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
        self.domain = "agentpay.it.com" # Tu dominio autenticado estándar

    def create_identity(self, agent_id, needs_phone=False):
        """Genera un email corporativo limpio y profesional."""
        # Alias for backward compatibility
        return self.create_certified_identity(agent_id)

    def create_certified_identity(self, agent_id, provider="AgentPay Secure Mail"):
        """
        Genera una IDENTIDAD CERTIFICADA (No desechable).
        - Email persistente @agentpay.it.com
        - Vinculación legal (Passport)
        - Capacidad de recibir OTPs
        """
        # Limpiamos el ID para usarlo en el email
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

        # Guardamos la relación en Supabase
        if self.db:
            try:
                # Upsert para no duplicar si ya existe
                self.db.table("identities").upsert({
                    "agent_id": agent_id,
                    "identity_id": identity_data['identity_id'],
                    "email": email_address,
                    "provider": provider,
                    "status": "active_certified"
                }).execute()
            except Exception as e:
                print(f"⚠️ Error persistiendo identidad certificada: {e}")

        return identity_data

    def parse_inbound_email(self, email_content):
        """
        Procesa el contenido crudo de un email (Subject + Body) y extrae OTPs/Links.
        Usa IA para entender formatos complejos (ej. "Tu código es 1234" vs "567 es tu código").
        """
        # Si recibimos un diccionario (simulado o de webhook)
        if isinstance(email_content, dict):
            subject = email_content.get('subject', '')
            body = email_content.get('body', '') or email_content.get('text', '')
        else:
            # String crudo
            subject = "Raw Inbound"
            body = str(email_content)

        return self._extract_code_with_ai(subject, body)

    def _extract_code_with_ai(self, subject, body):
        """
        Usa GPT-4o Mini para leer el email y sacar solo el código.
        """
        if not client:
            # Fallback regex simple si no hay IA
            import re
            match = re.search(r'\b\d{6}\b', body)
            return match.group(0) if match else "NO_IA_NO_CODE"
            
        try:
            prompt = f"""
            Analiza este email y extrae ÚNICAMENTE el código de verificación numéricoo alfanumérico (OTP, PIN, Code).
            Si es un enlace de activación, extrae la URL completa.
            
            ASUNTO: {subject}
            CUERPO: {body}
            
            Responde SOLO con el código o URL limpia. Si no encuentras nada relevante, responde "NO_CODE".
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

    # --- UNIVERSAL NAVIGATOR FEATURES (PHASE 5) ---
    
    def get_residential_proxy(self, region="US"):
        """
        Provee una IP residencial limpia para evitar bloqueos por geolocalización.
        En producción: Conectar con Bright Data / Oxylabs API.
        """
        auth = os.environ.get("BRIGHTDATA_AUTH")
        if not auth:
            return {"status": "ERROR", "message": "Configuration Error: BRIGHTDATA_AUTH missing. Cannot provision real residential proxy."}
            
        # Conexión Real a Bright Data / Smartproxy
        session_id = f"sess_{int(time.time())}"
        proxy_url = f"http://{auth}-country-{region.lower()}:{session_id}@brd.superproxy.io:22225"
        
        return {
            "status": "ACTIVE",
            "region": region,
            "type": "RESIDENTIAL_ISP",
            "proxy_url": proxy_url,
            "expires_in": 300 # segundos
        }

    def solve_captcha(self, image_url):
        """
        Resuelve Captchas visuales usando IA Vision.
        En producción: Conectar con 2Captcha o GPT-4o-Vision.
        """
        if not client:
             return {"status": "ERROR", "message": "Configuration Error: OPENAI_API_KEY missing. AI Vision unavailable."}

        try:
            # Usamos GPT-4o para intentar resolver el desafío visual
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {
                        "role": "user", 
                        "content": [
                            {"type": "text", "text": "Solve this captcha challenge. If it's alphanumeric, return the text. If it's 'select images', return descriptions of selected grids coordinates."},
                            {"type": "image_url", "image_url": {"url": image_url}}
                        ]
                    }
                ],
                max_tokens=50
            )
            solution = response.choices[0].message.content
            return {"status": "SOLVED", "solution": solution}
            
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    # --- SESSION PERSISTENCE (COOKIES & TOKENS) ---
    def save_session(self, agent_id, cookies_blob):
        """
        Guarda el estado de navegación (Cookies, LocalStorage) para continuidad.
        """
        try:
            if self.db:
                self.db.table("identities").update({"session_blob": cookies_blob}).eq("agent_id", agent_id).execute()
            print(f"💾 [IDENTITY] Sesión guardada para {agent_id}")
            return True
        except Exception as e:
            print(f"⚠️ Error saving session: {e}")
            return False

    def recover_session(self, agent_id):
        """
        Recupera la sesión previa para evitar logines repetidos (Rate Limits).
        """
        try:
            if self.db:
                resp = self.db.table("identities").select("session_blob").eq("agent_id", agent_id).execute()
                if resp.data and resp.data[0].get('session_blob'):
                    print(f"♻️ [IDENTITY] Sesión recuperada para {agent_id}")
                    return resp.data[0]['session_blob']
            return None
        except Exception as e:
            return None

    def generate_digital_fingerprint(self):
        """
        Genera una huella digital de navegador humano para evitar detección de bots.
        """
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
        ]
        
        resolutions = ["1920x1080", "2560x1440", "1366x768"]
        langs = ["en-US", "es-ES", "fr-FR", "de-DE"]
        
        return {
            "User-Agent": random.choice(user_agents),
            "Accept-Language": f"{random.choice(langs)};q=0.9",
            "Screen-Resolution": random.choice(resolutions),
            "Timezone-Offset": "-480" # Simulated PST
        }
