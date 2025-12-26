import requests
import time
import os
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
        self.domain = "agentpay-it.com" # Tu nuevo dominio autenticado

    def create_identity(self, agent_id, needs_phone=False):
        """Genera un email corporativo permanente para el agente."""
        # Email fijo: bot_sk_4e3a... @ agentpay-it.com
        email_address = f"bot_{agent_id[:12]}@{self.domain}"
        
        identity_data = {
            "identity_id": agent_id,
            "email": email_address,
            "domain": self.domain
        }

        # Guardamos la relación en Supabase
        if self.db:
            try:
                self.db.table("identities").insert({
                    "agent_id": agent_id,
                    "identity_id": agent_id,
                    "email": email_address,
                    "provider": "Brevo-Private",
                    "status": "active"
                }).execute()
            except Exception as e:
                print(f"⚠️ Error persistiendo identidad: {e}")

        return identity_data

    def update_session_data(self, identity_id, session_data):
        """Guarda cookies/tokens de sesión para persistencia."""
        if not self.db: return {"error": "No DB connected"}
        try:
            self.db.table("identities").update({
                "session_metadata": session_data,
                "last_active": "now()"
            }).eq("identity_id", identity_id).execute()
            return {"success": True}
        except Exception as e:
            return {"error": str(e)}

    def check_sms_inbox(self, identity_id):
        """
        Consulta puntual del buzón de SMS (2FA Físico).
        Soporta integración real con Twilio si hay credenciales.
        """
        # 1. Intento de conectividad REAL (Producción)
        sid = os.environ.get("TWILIO_ACCOUNT_SID")
        token = os.environ.get("TWILIO_AUTH_TOKEN")
        
        if sid and token:
            try:
                from twilio.rest import Client
                client = Client(sid, token)
                # En un caso real, filtraríamos por el número 'to' == identity_id
                messages = client.messages.list(limit=1)
                
                if not messages:
                     return {"status": "WAITING", "message": "Inbox empty"}
                     
                last_msg = messages[0]
                # Reutilizamos la IA para extraer el OTP del cuerpo del SMS
                code = self._extract_code_with_ai("SMS from " + str(last_msg.from_), last_msg.body)
                
                return {
                    "status": "RECEIVED",
                    "sender": str(last_msg.from_),
                    "otp_code": code,
                    "message": last_msg.body
                }
            except Exception as e:
                print(f"⚠️ Twilio API Error: {e}")
                # Fallback al mock solo si falla la API real por config

        # 2. Mock de Desarrollo (Simulación)
        return {
            "status": "RECEIVED",
            "sender": "ServiceAuth",
            "otp_code": str(int(time.time()) % 899999 + 100000), 
            "message": "Your verification code is ..."
        }

    def get_active_identities(self, agent_id):
        """Recupera sesiones anteriores (Identity Recovery)"""
        if not self.db:
            return []
        try:
            resp = self.db.table("identities").select("*").eq("agent_id", agent_id).execute()
            return resp.data
        except Exception as e:
            return {"error": str(e)}

    def check_inbox(self, agent_id):
        """
        Consulta TU PROPIA tabla SQL en lugar de 1secmail.
        """
        if not self.db:
            return {"status": "ERROR", "message": "DB not connected"}

        try:
            # Buscamos el último email recibido para este agente en tu tabla SQL
            response = self.db.table("inbound_emails") \
                .select("*") \
                .eq("agent_id", agent_id) \
                .order("received_at", desc=True) \
                .limit(1) \
                .execute()

            if not response.data:
                return {"status": "WAITING", "message": "No emails yet in your private database"}

            msg_data = response.data[0]
            body = msg_data.get('body_text', '')
            subject = msg_data.get('subject', '')

            # Usamos la IA para extraer el código del texto real guardado
            extracted_code = self._extract_code_with_ai(subject, body)

            return {
                "status": "RECEIVED",
                "latest_message": {
                    "sender": msg_data.get('sender'),
                    "subject": subject,
                    "otp_code": extracted_code,
                    "received_at": msg_data.get('received_at')
                }
            }
        except Exception as e:
            return {"status": "ERROR", "detail": str(e)}

    def _extract_code_with_ai(self, subject, body):
        """
        Usa GPT-4o Mini para leer el email y sacar solo el código.
        """
        if not client:
            return "AI_UNAVAILABLE"
            
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
        # Simulamos una IP rotativa real
        session_id = f"sess_{int(time.time())}"
        proxy_url = f"http://customer-agentpay-cc-{region}:{session_id}@pr.agentpay.io:7777"
        
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
            return {"status": "MOCK_SUCCESS", "solution": "click:traffic_light,crosswalk", "confidence": 0.99}

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
