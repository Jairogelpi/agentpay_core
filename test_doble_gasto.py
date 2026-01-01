import requests
import uuid
import os
import json

# --- CONFIGURACIÓN ---
API_URL = "https://agentpay-core.onrender.com"

def test_doble_gasto():
    print("\n🧪 --- TEST DE IDEMPOTENCIA (DOBLE GASTO) ---")

    # 1. REGISTRO (Para tener agente y API Key)
    print("1️⃣  Registrando agente de prueba...")
    try:
        reg = requests.post(f"{API_URL}/v1/agent/register", json={
            "client_name": "Idempotency Tester",
            "country_code": "US"
        }).json()
        
        if reg.get("status") == "ERROR":
            print(f"❌ Error registro: {reg}")
            return
            
        agent_id = reg['agent_id']
        api_key = reg['api_key']
        print(f"   ✅ Agente: {agent_id}")
        
    except Exception as e:
        print(f"❌ Error fatal conectando: {e}")
        return

    # 2. RECARGA FONDOS (Para poder pagar)
    print("2️⃣  Recargando fondos ($50)...")
    requests.post(f"{API_URL}/v1/topup/direct_charge", json={
        "agent_id": agent_id,
        "amount": 50.00,
        "payment_method_id": "pm_card_visa"
    })

    # 3. LANZAR ATAQUE DOBLE
    unique_tx_id = str(uuid.uuid4())
    print(f"   🔑 Idempotency-Key Generada: {unique_tx_id}")
    
    payload = {
        "vendor": "Double-Dip-Shop",
        "amount": 10.0,
        "description": "Un solo producto",
        "justification": "Test Idempotencia"
    }
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Idempotency-Key": unique_tx_id
    }

    print(f"\n3️⃣  Lanzando Petición A...")
    res1 = requests.post(f"{API_URL}/v1/pay", json=payload, headers=headers).json()
    print(f"   Respuesta A: {res1.get('status')} | Balance: {res1.get('balance')}")

    print(f"\n4️⃣  Lanzando Petición B (Mismo Header)...")
    res2 = requests.post(f"{API_URL}/v1/pay", json=payload, headers=headers).json()
    print(f"   Respuesta B: {res2.get('status')} | Balance: {res2.get('balance')}")

    # VERIFICACIÓN
    bal1 = float(res1.get('balance', 0) or 0)
    bal2 = float(res2.get('balance', 0) or 0)

    if bal1 == bal2:
        print(f"\n✅ ÉXITO: El saldo NO cambió ({bal1} == {bal2}). El sistema detectó la duplicidad.")
    else:
        print(f"\n❌ FALLO: El saldo cambió ({bal1} != {bal2}). ¡Se cobró dos veces!")

if __name__ == "__main__":
    test_doble_gasto()
