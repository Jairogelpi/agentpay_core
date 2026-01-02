import requests
import time
import sys

# Configuración
API_URL = "https://agentpay-core.onrender.com"
EMAIL_ALERTA = "jairogelpi@gmail.com" # Tu correo donde llegará el botón
VENDOR_GRIS = "Amazon_Web_Services"

def ejecutar_test():
    print("🤖 --- AGENTPAY: TEST DE APRENDIZAJE EN VIVO ---")

    # 1. REGISTRO
    print("\n1️⃣  Registrando nuevo agente...")
    reg = requests.post(f"{API_URL}/v1/agent/register", json={
        "client_name": "Test Aprendizaje Real",
        "country_code": "ES"
    }).json()
    
    agent_id = reg['agent_id']
    api_key = reg['api_key']
    headers = {"Authorization": f"Bearer {api_key}"}
    print(f"   ✅ Agente: {agent_id}")

    # 2. CONFIGURAR EMAIL Y SALDO
    print(f"\n2️⃣  Asociando email {EMAIL_ALERTA} y cargando $5,000...")
    requests.post(f"{API_URL}/v1/agent/settings", json={"agent_id": agent_id, "owner_email": EMAIL_ALERTA})
    requests.post(f"{API_URL}/v1/topup/auto", json={"agent_id": agent_id, "amount": 5000.0})

    # 3. PRIMER INTENTO (COMPRA GRIS)
    print(f"\n3️⃣  Intentando compra 'gris' de $3,500 en {VENDOR_GRIS}...")
    payload = {
        "vendor": VENDOR_GRIS,
        "amount": 3500.0,
        "description": "Servidores de cómputo GPU",
        "justification": "Proyecto de IA"
    }
    
    res1 = requests.post(f"{API_URL}/v1/pay", json=payload, headers=headers).json()
    print(f"   📝 Respuesta servidor: {res1.get('status')}")
    
    print("\n---------------------------------------------------------")
    print("📢 ¡ACCIÓN REQUERIDA EN LA VIDA REAL!")
    print(f"1. Abre tu Gmail ({EMAIL_ALERTA}).")
    print(f"2. Busca el correo de gelpierreape@gmail.com.")
    print("3. Haz clic en el botón 'APROBAR Y ENSEÑAR A LA IA'.")
    print("---------------------------------------------------------")
    
    input("\n👉 Una vez hayas hecho clic en el email, presiona ENTER aquí para verificar el aprendizaje...")

    # 4. SEGUNDO INTENTO (LA IA YA DEBERÍA SABERLO)
    print(f"\n4️⃣  Repitiendo la misma compra de $3,500...")
    res2 = requests.post(f"{API_URL}/v1/pay", json=payload, headers=headers).json()
    
    final_status = res2.get('status')
    if final_status == "APPROVED":
        print(f"\n✅ ¡PRUEBA SUPERADA! La IA aprendió de tu clic.")
        print(f"   Estado final: {final_status} (Sin intervención humana)")
    else:
        print(f"\n❌ Algo falló. El estado es {final_status}. Revisa los logs de Render.")

if __name__ == "__main__":
    ejecutar_test()