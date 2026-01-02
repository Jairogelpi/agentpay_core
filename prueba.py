import requests
import time

BASE_URL = "https://agentpay-core.onrender.com"
MI_EMAIL = "jairogelpi@gmail.com"

def run_learning_test():
    print("🧠 --- TEST DE APRENDIZAJE Y OPTIMIZACIÓN DE LATENCIA ---")

    # 1. REGISTRO
    print("\n1️⃣ Registrando Agente de Análisis de Datos...")
    reg = requests.post(f"{BASE_URL}/v1/agent/register", json={
        "client_name": "Data_Analyst_Agent_007",
        "country": "ES"
    }).json()
    
    agent_id = reg['agent_id']
    api_key = reg['api_key']
    headers = {"Authorization": f"Bearer {api_key}"}

    requests.post(f"{BASE_URL}/v1/agent/settings", json={
        "agent_id": agent_id,
        "owner_email": MI_EMAIL,
        "agent_role": "Data Scientist and Machine Learning Engineer"
    })

    requests.post(f"{BASE_URL}/v1/topup/auto", json={"agent_id": agent_id, "amount": 1000.0})

    # --- FASE DE APRENDIZAJE ---

    # COMPRA 1: El Oráculo debe pensar (Latencia alta esperada)
    print("\n2️⃣ Primera compra en 'Google Cloud' (Fase de Entrenamiento)...")
    payload = {
        "vendor": "cloud.google.com",
        "amount": 50.0,
        "description": "Compute Engine Instance Usage",
        "justification": "Necesario para entrenar el modelo de predicción de ventas."
    }
    
    start_1 = time.time()
    res_1 = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json=payload).json()
    end_1 = time.time()
    
    latencia_1 = end_1 - start_1
    print(f"   📊 Resultado: {res_1.get('status')}")
    print(f"   ⏱️ Latencia (IA pensando): {latencia_1:.2f}s")

    print("\n--- Esperando 5 segundos para que la auditoría background complete el aprendizaje... ---")
    time.sleep(5)

    # COMPRA 2: El sistema ya debe confiar (Latencia ultra-baja esperada)
    print("\n3️⃣ Segunda compra en 'Google Cloud' (Verificación de Aprendizaje)...")
    payload["amount"] = 75.0
    payload["description"] = "Additional Storage for BigQuery"
    
    start_2 = time.time()
    res_2 = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json=payload).json()
    end_2 = time.time()
    
    latencia_2 = end_2 - start_2
    print(f"   📊 Resultado: {res_2.get('status')}")
    print(f"   ⏱️ Latencia (Modo Trusted): {latencia_2:.2f}s")

    # COMPARATIVA FINAL
    print("\n📈 --- RESULTADOS DEL APRENDIZAJE ---")
    if latencia_2 < latencia_1:
        ahorro = ((latencia_1 - latencia_2) / latencia_1) * 100
        print(f"   ✅ ÉXITO: La segunda transacción fue un {ahorro:.1f}% más rápida.")
        print("   🧠 El sistema ha reconocido al vendedor y ha evitado llamadas innecesarias a la IA.")
    else:
        print("   ⚠️ La latencia no bajó significativamente. Verifica si 'add_to_trusted_services' se ejecutó en los logs.")

if __name__ == "__main__":
    run_learning_test()