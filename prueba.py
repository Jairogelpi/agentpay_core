import requests
import time
import json

# Configuración - Asegúrate de que tu servidor en Render/Local esté activo
BASE_URL = "http://localhost:8000" # O tu URL de Render
MI_EMAIL = "tu-email@ejemplo.com" # Cambia esto por tu email real

def run_real_world_test():
    print("🌍 --- INICIANDO ESCENARIO DE VIDA REAL: AgentPay Core ---")

    # PASO 1: Registro del Agente y Configuración de Identidad
    print("\n1️⃣  Registrando Agente con Identidad Legal...")
    reg_res = requests.post(f"{BASE_URL}/v1/agent/register", json={
        "client_name": "AI_Research_Agent_001",
        "country": "ES"
    }).json()
    
    agent_id = reg_res['agent_id']
    api_key = reg_res['api_key']
    headers = {"Authorization": f"Bearer {api_key}"}
    print(f"   ✅ Agente ID: {agent_id}")

    # Configurar email para alertas y aprendizaje
    requests.post(f"{BASE_URL}/v1/agent/settings", json={
        "agent_id": agent_id,
        "owner_email": MI_EMAIL
    })

    # PASO 2: Carga de Saldo (Simulando entrada de dinero real)
    print("\n2️⃣  Cargando Saldo Inicial ($1,000.00)...")
    requests.post(f"{BASE_URL}/v1/topup/auto", json={
        "agent_id": agent_id,
        "amount": 1000.0
    })

    # PASO 3: Intento de Pago con Auditoría OSINT e IA
    # Vamos a usar un dominio real para que el motor OSINT pueda investigarlo
    print("\n3️⃣  El Agente intenta comprar en 'HuggingFace.co' (Monto: $500.00)...")
    
    pay_payload = {
        "vendor": "huggingface.co",
        "vendor_url": "https://huggingface.co",
        "amount": 500.0,
        "description": "Suscripción anual a GPU Clusters para entrenamiento",
        "justification": "Necesito potencia de cómputo para procesar el dataset de enero."
    }

    response = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json=pay_payload).json()
    
    print(f"   📊 Resultado del Sistema: {response.get('status')}")
    print(f"   📝 Razón: {response.get('message') or response.get('reason')}")

    # PASO 4: Verificación de Evidencia Forense
    if response.get('status') == "APPROVED_PENDING_AUDIT":
        print("\n4️⃣  Generando Paquete de Evidencia Forense (CSI)...")
        # Esperamos un segundo a que la tarea en background procese
        time.sleep(2)
        audit_res = requests.get(f"{BASE_URL}/v1/agent/{agent_id}/audit_bundle").json()
        print(f"   ✅ Bundle ID: {audit_res['bundle_id']}")
        print(f"   ✅ Hash de Integridad: {audit_res['integrity_hash'][:20]}...")
        
        print("\n📢  PRUEBA EN CURSO: Revisa tu email para aprobar la transacción.")
        print("    Una vez aprobada, el sistema 'aprenderá' que HuggingFace es seguro.")

if __name__ == "__main__":
    run_real_world_test()