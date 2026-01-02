import requests
import time

BASE_URL = "https://agentpay-core.onrender.com" # Cambia a tu URL local si es necesario

def run_real_test():
    print("🌍 --- INICIANDO ESCENARIO REAL ---")

    # 1. Registro Automático (Genera su propia API Key)
    print("\n1️⃣ Registrando Agente...")
    reg_res = requests.post(f"{BASE_URL}/v1/agent/register", json={
        "client_name": "Agente_Prueba_Real",
        "country": "ES"
    }).json()
    
    agent_id = reg_res['agent_id']
    api_key = reg_res['api_key']
    headers = {"Authorization": f"Bearer {api_key}"}
    print(f"✅ Agente registrado: {agent_id}")

    # 2. Carga de Saldo Real (Top-up)
    print("\n2️⃣ Cargando Saldo...")
    requests.post(f"{BASE_URL}/v1/topup/auto", json={
        "agent_id": agent_id,
        "amount": 1000.0
    })

    # 3. Pago Real con Emisión de Tarjeta Virtual
    # Este escenario activará la Psicología Forense y el OSINT
    print("\n3️⃣ Ejecutando Pago (HuggingFace)...")
    payload = {
        "vendor": "huggingface.co",
        "vendor_url": "https://huggingface.co",
        "amount": 150.0,
        "description": "Suscripción GPU para entrenamiento de modelos",
        "justification": "Necesario para el pipeline de IA del proyecto actual."
    }

    response = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json=payload).json()
    
    print(f"📊 Resultado: {response.get('status')}")
    print(f"💳 Tarjeta Stripe: {response.get('card', {}).get('id', 'No emitida')}")

    # 4. Generación de Evidencia Forense
    print("\n4️⃣ Generando Bundle Forense...")
    time.sleep(2) # Espera a la auditoría background
    bundle = requests.get(f"{BASE_URL}/v1/agent/{agent_id}/audit_bundle").json()
    print(f"✅ Hash CSI: {bundle.get('integrity_hash')}")

if __name__ == "__main__":
    run_real_test()