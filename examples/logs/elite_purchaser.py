
import os
import time
import json
import requests
from openai import OpenAI
from dotenv import load_dotenv

# Cargamos el entorno EXCLUSIVO del agente (sus propias llaves)
env_path = os.path.join(os.path.dirname(__file__), ".env.agent")
load_dotenv(dotenv_path=env_path)

# CONFIGURACIÓN
HOST = "https://agentpay-core.onrender.com"
AGENT_NAME = "Elite_Purchaser_v2"
LOG_FILE = os.path.join(os.path.dirname(__file__), "agent.log")

# La IA del agente usa SU PROPIA LLAVE configuara en .env.agent
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

def agent_log(msg):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"[{timestamp}] {msg}"
    print(formatted_msg)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(formatted_msg + "\n")

class EliteAgent:
    def __init__(self):
        self.api_key = None
        
    def setup(self):
        agent_log(f"--- INICIALIZANDO AGENTE: {AGENT_NAME} ---")
        # Registro real en la infraestructura
        r = requests.post(f"{HOST}/v1/agent/register", json={"client_name": AGENT_NAME})
        
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "ERROR":
                raise Exception(f"❌ Error de Registro en Servidor: {data.get('message')}")
            
            self.api_key = data.get("api_key")
            if not self.api_key:
                raise Exception("❌ Error de Registro: No se recibió API Key en la respuesta.")
            agent_log(f"Wallet vinculada. API Key: {self.api_key}")
        else:
            raise Exception(f"❌ Error HTTP en Registro: {r.status_code} - {r.text[:100]}")

    def mission_control(self, objective):
        agent_log(f"OBJETIVO RECIBIDO: {objective}")
        
        # EL AGENTE PIENSA (IA REAL)
        completion = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "Eres un agente de compras autónomo. Decides qué comprar y justificas el gasto."},
                {"role": "user", "content": f"Tu misión es: {objective}. Formula un plan de compra detallado."}
            ]
        )
        plan = completion.choices[0].message.content
        agent_log(f"PLAN DE LA IA:\n{plan}")

        # Ejecutamos el pago a través de AgentPay
        agent_log("Solicitando autorización financiera...")
        
        # Simulamos que la IA extrae los datos del plan
        payload = {
            "agent_id": self.api_key,
            "vendor": "cloud-services.com",
            "amount": 15.00,
            "description": "Compute Units for Data Analysis",
            "justification": "Necesitamos potencia de cálculo para procesar el set de datos objetivo."
        }
        
        r = requests.post(f"{HOST}/v1/pay", json=payload)
        auth_data = r.json()
        
        if auth_data.get("success"):
            agent_log("🏦 INFRAESTRUCTURA: Pago Aprobado por El Oráculo.")
            agent_log(f"🏦 RAZÓN DEL ORÁCULO: {auth_data.get('message')}")
            
            card = auth_data.get("card")
            if card:
                agent_log(f"💳 TARJETA VIRTUAL EMITIDA: {card.get('number')} (CVV: {card.get('cvv')})")
                agent_log(f"🛡️ RESTRICCIÓN MCC APLICADA: {auth_data.get('mcc_category', 'N/A')}")
            else:
                agent_log("⚠️ ATENCIÓN: El pago fue aprobado pero no se recibieron los detalles de la tarjeta.")
            
            # SIMULACIÓN DE COMPRA REAL
            agent_log("🛒 CONECTANDO CON EL PROVEEDOR (Simulado)...")
            time.sleep(2)
            agent_log("✅ COMPRA REALIZADA EXITOSAMENTE.")
            
            # Verificación Forense
            agent_log(f"⚖️ AUDITORÍA GENERADA: {auth_data.get('forensic_url')}")
        else:
            agent_log(f"❌ INFRAESTRUCTURA: Pago Rechazado. Motivo: {auth_data.get('message')}")

if __name__ == "__main__":
    agent = EliteAgent()
    agent.setup()
    agent.mission_control("Adquirir recursos de computación para un análisis de datos crítico.")
