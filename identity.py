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

    def create_identity(self, agent_id):
        """
        Crea un email temporal único para este agente.
        """
        # Para el MVP, generamos un usuario aleatorio
        # 1secmail refresca dominios, pero usaremos el por defecto
        email_user = f"agent_{agent_id}_{int(time.time())}"
        domain = "1secmail.com" 
        email_address = f"{email_user}@{domain}"
        
        # PERSISTENCIA (Para recuperación de sesiones)
        if self.db:
            try:
                self.db.table("identities").insert({
                    "agent_id": agent_id,
                    "identity_id": email_user,
                    "email": email_address,
                    "provider": domain,
                    "created_at": "now()",
                    "status": "active"
                }).execute()
            except Exception as e:
                print(f"⚠️ Warning persisting identity: {e}")

        return {
            "identity_id": email_user, # Usamos el user como ID para recuperar mensajes luego
            "email": email_address,
            "domain": domain
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

    def check_inbox(self, identity_id, domain="1secmail.com"):
        """
        Revisa el buzón y usa GPT-4 para extraer códigos.
        """
        # 1. Consultamos la API del proveedor de email
        url = f"https://www.1secmail.com/api/v1/?action=getMessages&login={identity_id}&domain={domain}"
        
        try:
            resp = requests.get(url).json()
            
            if not resp:
                return {"status": "WAITING", "message": "No emails yet"}
            
            # 2. Si hay mensajes, leemos el último
            last_msg_id = resp[0]['id']
            msg_url = f"https://www.1secmail.com/api/v1/?action=readMessage&login={identity_id}&domain={domain}&id={last_msg_id}"
            msg_data = requests.get(msg_url).json()
            
            body = msg_data.get('textBody', '') or msg_data.get('body', '')
            subject = msg_data.get('subject', '')

            # 3. MAGIA: Usamos TU IA para extraer el código, no el texto sucio
            extracted_code = self._extract_code_with_ai(subject, body)

            return {
                "status": "RECEIVED",
                "latest_message": {
                    "sender": msg_data.get('from'),
                    "subject": subject,
                    "otp_code": extracted_code, # <--- ESTO ES LO QUE VALE DINERO
                    "snippet": body[:100] + "..."
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
