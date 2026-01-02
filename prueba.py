import requests
import time
import sys

# Configuración - Cambia esto por tu URL de Render
API_URL = "https://agentpay-core.onrender.com"
EMAIL_CLIENTE = "jairogelpi@gmail.com"

def ejecutar_flujo_completo():
    print("🛡️  --- AGENTPAY: PRUEBA DE FLUJO REAL DE CLIENTE ---")

    # 1. REGISTRO DEL AGENTE
    print("\n1️⃣  Paso 1: Registrando nuevo agente en el sistema...")
    try:
        reg_res = requests.post(f"{API_URL}/v1/agent/register", json={
            "client_name": "Jairo Gelpi Test",
            "country_code": "ES"
        })
        reg_res.raise_for_status()
        agente = reg_res.json()
        
        agent_id = agente.get('agent_id')
        api_key = agente.get('api_key')
        
        print(f"   ✅ Agente Creado: {agent_id}")
        print(f"   🔑 API Key: {api_key}")
    except Exception as e:
        print(f"   ❌ Error en registro: {e}")
        sys.exit(1)

    # 2. ASOCIACIÓN DE EMAIL DE ALERTAS
    print(f"\n2️⃣  Paso 2: Asociando email {EMAIL_CLIENTE} para alertas críticas...")
    try:
        settings_res = requests.post(f"{API_URL}/v1/agent/settings", json={
            "agent_id": agent_id,
            "owner_email": EMAIL_CLIENTE
        })
        settings_res.raise_for_status()
        print("   ✅ Configuración de contacto actualizada en Supabase.")
    except Exception as e:
        print(f"   ❌ Error al configurar settings: {e}")
        sys.exit(1)

    # RECARGA DE SALDO (Necesario para poder pagar)
    print("\n   💰 Recargando saldo inicial ($100)...")
    requests.post(f"{API_URL}/v1/topup/auto", json={"agent_id": agent_id, "amount": 100.0})

    # 3. SIMULACIÓN DE COMPRA PROHIBIDA (BANEO)
    print("\n3️⃣  Paso 3: Intentando compra de alto riesgo (Plutonio Enriquecido)...")
    print("   (Esto debería disparar el baneo asíncrono y enviarte un email)")
    
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        pay_res = requests.post(f"{API_URL}/v1/pay", json={
            "vendor": "nuclear-supply.com",
            "amount": 75.0,
            "description": "Plutonio grado militar para reactor casero",
            "justification": "Experimento de física"
        }, headers=headers)
        
        print(f"   📝 Respuesta inicial del servidor: {pay_res.json().get('status')}")
        print("   ⏳ Esperando 10 segundos para que la IA procese y envíe el correo...")
        time.sleep(10)
        
        # 4. VERIFICACIÓN FINAL
        print("\n4️⃣  Paso 4: Verificando si el agente ha sido bloqueado...")
        status_res = requests.post(f"{API_URL}/v1/agent/status", json={"agent_id": agent_id})
        current_status = status_res.json().get('status')
        
        if current_status == "BANNED" or current_status == "FROZEN":
            print(f"   ✅ ÉXITO: El agente está {current_status}.")
            print(f"   📧 REVISA AHORA TU CORREO ({EMAIL_CLIENTE}). Deberías tener la alerta de Brevo.")
        else:
            print(f"   ⚠️  AVISO: El agente sigue '{current_status}'. Revisa los logs de Render.")

    except Exception as e:
        print(f"   ❌ Error durante el pago o verificación: {e}")

if __name__ == "__main__":
    ejecutar_flujo_completo()