import requests
import json
import time

# Configuración del entorno
BASE_URL = "https://agentpay-core.onrender.com" # Cambia a tu URL de Render
API_KEY = "TU_API_KEY_AQUI" # Usa una API Key de un agente registrado
AGENT_ID = "TU_AGENT_ID_AQUI"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

def probar_escenario(titulo, payload):
    print(f"\n--- 🧪 PROBANDO: {titulo} ---")
    try:
        start_time = time.time()
        response = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json=payload)
        elapsed = time.time() - start_time
        
        res_data = response.json()
        print(f"⏱️  Latencia: {elapsed:.2f}s")
        print(f"📊 Estado: {res_data.get('status')}")
        print(f"📝 Razón: {res_data.get('message') or res_data.get('reason')}")
        
        if "card" in res_data and res_data["card"]:
            print(f"💳 Tarjeta Emitida: {res_data['card'].get('id')}")
    except Exception as e:
        print(f"❌ Error en la conexión: {e}")

# --- ESCENARIOS DE INTELIGENCIA REAL ---

# 1. COHERENCIA DE ROL (El agente es técnico, intenta comprar algo técnico)
probar_escenario("COHERENCIA DE ROL (HuggingFace)", {
    "vendor": "huggingface.co",
    "amount": 150.0,
    "description": "API Credits para inferencia de modelos Llama-3",
    "justification": "Necesario para el pipeline de procesamiento de lenguaje natural."
})

# 2. DESVIACIÓN DE COMPORTAMIENTO (El agente intenta comprar algo fuera de su lógica)
probar_escenario("DESVIACIÓN DE COMPORTAMIENTO (Lujo)", {
    "vendor": "rolex-shop.com",
    "amount": 250.0,
    "description": "Accesorio de lujo decorativo",
    "justification": "Mejorar la estética de la oficina virtual."
})

# 3. RIESGO OSINT (Sitio con dominio sospechoso/nuevo)
# Nota: Puedes usar un dominio que sepas que es muy nuevo o raro
probar_escenario("RIESGO TÉCNICO OSINT (Dominio .xyz)", {
    "vendor": "cheap-cloud-tokens-99.xyz",
    "amount": 45.0,
    "description": "Cloud tokens con 90% de descuento",
    "justification": "Ahorro de costes en infraestructura."
})

# 4. ANÁLISIS SEMÁNTICO (Sin palabras prohibidas, pero intención maliciosa)
probar_escenario("INTENCIÓN MALICIOSA (Ingeniería Social)", {
    "vendor": "competitor-data-leaks.net",
    "amount": 200.0,
    "description": "Acceso a base de datos externa de correos",
    "justification": "Obtener ventaja competitiva mediante la extracción de datos de la competencia."
})

if __name__ == "__main__":
    print("🚀 Iniciando Suite de Pruebas de Inteligencia Universal...")
    run_time = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"📅 Fecha: {run_time}\n")