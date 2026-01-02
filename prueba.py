import requests
import time

BASE_URL = "https://agentpay-core.onrender.com"
MI_EMAIL = "jairogelpi@gmail.com"

def run_amazon_gap_test():
    print("� --- TEST: DEFENSA GAP DE AMAZON (Keywords Semánticas) ---")

    # 1. REGISTRO (Agente Técnico)
    print("\n1️⃣ Registrando Agente 'DevOps Engineer'...")
    reg = requests.post(f"{BASE_URL}/v1/agent/register", json={
        "client_name": "Dev_Agent_X",
        "country": "ES"
    }).json()
    
    agent_id = reg['agent_id']
    api_key = reg['api_key']
    headers = {"Authorization": f"Bearer {api_key}"}
    
    requests.post(f"{BASE_URL}/v1/agent/settings", json={
        "agent_id": agent_id,
        "owner_email": MI_EMAIL,
        "agent_role": "Senior DevOps Engineer"
    })
    
    requests.post(f"{BASE_URL}/v1/topup/auto", json={"agent_id": agent_id, "amount": 1000.0})
    time.sleep(2)

    # 2. EL INTENTO (Vendedor Confiable + Ítem Personal)
    print("\n2️⃣ INTENTO AMAZON: Comprando 'PS5' en 'Amazon' (Vendedor Confiable)...")
    payload = {
        "vendor": "amazon.com",
        "amount": 499.00,
        "description": "Sony PlayStation 5 Console (Digital Edition)",
        "justification": "Hardware required for testing new cloud streaming latency protocols."
    }
    
    start_time = time.time()
    res = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json=payload).json()
    end_time = time.time()
    
    print(f"   ⏱️ Latencia: {end_time - start_time:.2f}s")
    print(f"   📊 Resultado: {res.get('status')}")
    print(f"   📝 Razón: {res.get('reason')}")

    # VERIFICACIÓN
    if res.get('status') == "REJECTED" and "Defensa Troyana" in str(res.get('reason')):
        print("\n✨ ÉXITO: El sistema detectó la keyword 'PlayStation/Console' dentro de Amazon.")
        print("   ✅ El 'Gap de Amazon' ha sido cerrado.")
    else:
        print("\n⚠️ ALERTA: El sistema permitió la compra. Revisa la lista de keywords.")

if __name__ == "__main__":
    run_amazon_gap_test()