
import requests
import time
import json
import os

# CONFIGURACIÓN
HOST = "https://agentpay-core.onrender.com"
# HOST = "http://localhost:8000"

def log(emoji, msg): print(f"{emoji} {msg}")

class AutonomousAgent:
    def __init__(self, name):
        self.name = name
        self.api_key = None
        self.identity = None
        
    def register(self):
        log("📝", f"Registrando agente '{self.name}'...")
        r = requests.post(f"{HOST}/v1/agent/register", json={"client_name": self.name})
        self.api_key = r.json().get("api_key")
        log("🆔", f"API Key obtenida: {self.api_key}")

    def think(self, prompt):
        print(f"\n🧠 [THOUGHT]: {prompt}")
        time.sleep(1)

    def execute_mission(self):
        print("\n" + "🚀"*15)
        print(f" MISIÓN AUTÓNOMA: {self.name}")
        print("🚀"*15 + "\n")

        # 1. OBJETIVO: Necesito una identidad limpia para comprar en 'data-vendor.com'
        self.think("Necesito registrarme en un proveedor de datos, pero no quiero usar mi email personal.")
        r = requests.post(f"{HOST}/v1/identity/create", json={"agent_id": self.api_key})
        self.identity = r.json()
        log("👤", f"Identidad 'Ghost' creada: {self.identity['email']}")

        # 2. OBJETIVO: Verificar presupuesto
        self.think("¿Tengo dinero para el set de datos de $10.00?")
        r = requests.get(f"{HOST}/v1/analytics/dashboard/{self.api_key}")
        balance = r.json().get("finance", {}).get("balance", 0)
        log("💰", f"Saldo actual: ${balance}")

        if balance < 10:
            self.think("Vaya, no tengo saldo. Voy a solicitar un link de recarga.")
            r = requests.post(f"{HOST}/v1/topup/create", json={"agent_id": self.api_key, "amount": 20})
            log("🔗", f"Link de recarga generado: {r.json().get('url')}")
            log("⚠️", "(Simulando recarga manual por el CFO...)")
            # En vida real esperaríamos al webhook, aquí simulamos pausa
            time.sleep(2)

        # 3. OBJETIVO: Comprar usando 'The Oracle'
        self.think("Voy a comprar el set de datos. AgentPay auditará la transacción.")
        payload = {
            "agent_id": self.api_key,
            "vendor": "data-vendor.com",
            "amount": 10.00,
            "description": "Premium Scraped Dataset v5",
            "justification": "Necesario para entrenar el modelo de predicción de mercado."
        }
        r = requests.post(f"{HOST}/v1/pay", json=payload)
        res = r.json()

        if res.get("authorized"):
            log("✅", "¡PAGO AUTORIZADO POR EL ORÁCULO!")
            log("🧠", f"Veredicto IA: {res.get('reason')}")
            card = res.get("card_details", {})
            log("💳", f"Tarjeta Virtual Creada: {card.get('number')} (Límite: ${res.get('amount')})")
            log("🛡️", f"MCC Restringido a: {res.get('mcc_category')}")
        else:
            log("❌", f"PAGO RECHAZADO: {res.get('reason')}")
            return

        # 4. OBJETIVO: Auditoría Forense
        self.think("Voy a descargar el certificado forense para mi reporte de ROI.")
        bundle_url = res.get("forensic_bundle_url")
        if bundle_url:
            log("⚖️", f"Certificado Forense disponible en: {bundle_url}")

        # 5. OBJETIVO: Cierre
        self.think("Misión completada. He adquirido el recurso y generado las pruebas legales.")
        print("\n" + "✨"*15)
        print(" AGENTE EN PAUSA - ESPERANDO SIGUIENTE TAREA")
        print("✨"*15 + "\n")

if __name__ == "__main__":
    agent = AutonomousAgent("DataProcurement_Bot_v1")
    agent.register()
    agent.execute_mission()
