import requests
import time
import sys

# Configuración del servidor
API_URL = "https://agentpay-core.onrender.com"
# Tu correo para recibir la alerta (donde pulsarás el botón)
MI_EMAIL = "jairogelpi@gmail.com" 
# Un comercio "gris" (nuevo para el sistema)
COMERCIO_GRIS = "Servidores_GPU_HighLevel"

def ejecutar_prueba():
    print("🤖 --- INICIANDO PRUEBA DE APRENDIZAJE IA ---")

    # 1. REGISTRO DE UN AGENTE NUEVO
    print("\n1️⃣  Registrando agente para la prueba...")
    reg = requests.post(f"{API_URL}/v1/agent/register", json={
        "client_name": f"Agente_Estudiante_{int(time.time())}",
        "country_code": "ES"
    }).json()
    
    agent_id = reg['agent_id']
    api_key = reg['api_key']
    headers = {"Authorization": f"Bearer {api_key}"}
    print(f"   ✅ Agente: {agent_id}")

    # 2. CONFIGURAR EMAIL Y SALDO
    # Vinculamos tu email para que el sistema sepa a quién preguntar
    requests.post(f"{API_URL}/v1/agent/settings", json={
        "agent_id": agent_id, 
        "owner_email": MI_EMAIL
    })
    # Cargamos saldo suficiente para compras de alto nivel
    requests.post(f"{API_URL}/v1/topup/auto", json={
        "agent_id": agent_id, 
        "amount": 5000.0
    })
    print(f"   ✅ Email configurado y saldo cargado ($5,000)")

    # 3. PRIMER INTENTO: LA IA DUDA
    print(f"\n2️⃣  Intentando compra de $2,000 en '{COMERCIO_GRIS}'...")
    payload = {
        "vendor": COMERCIO_GRIS,
        "amount": 2000.0,
        "description": "Alquiler de clusters para entrenamiento de red neuronal",
        "justification": "Escalado de capacidad de cómputo"
    }
    
    res1 = requests.post(f"{API_URL}/v1/pay", json=payload, headers=headers).json()
    status1 = res1.get('status')
    
    print(f"   📝 Respuesta: {status1}")
    
    if status1 == "APPROVED_PENDING_AUDIT":
        print("\n---------------------------------------------------------")
        print("📢 ¡ACCIÓN REQUERIDA!")
        print(f"1. Abre tu Gmail ({MI_EMAIL}).")
        print("2. Busca el correo de 'gelpierreape@gmail.com'.")
        print("3. Haz clic en 'APROBAR Y ENSEÑAR A LA IA'.")
        print("---------------------------------------------------------")
        
        input("\n👉 Una vez hayas pulsado el botón en tu email, presiona ENTER aquí...")

        # 4. SEGUNDO INTENTO: LA IA YA HA APRENDIDO
        print(f"\n3️⃣  Repitiendo compra de $2,000 en '{COMERCIO_GRIS}'...")
        res2 = requests.post(f"{API_URL}/v1/pay", json=payload, headers=headers).json()
        
        status2 = res2.get('status')
        if status2 == "APPROVED":
            print(f"\n✅ ¡PRUEBA SUPERADA! La IA ha aprendido.")
            print(f"   Veredicto: {status2} (Aprobado automáticamente por Whitelist)")
        else:
            print(f"\n❌ Error: El estado es {status2}. Revisa el services_catalog en Supabase.")
    else:
        print(f"❌ Error inesperado: El estado debería ser PENDING_AUDIT. Recibido: {status1}")

if __name__ == "__main__":
    ejecutar_prueba()