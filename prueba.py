import requests
import time
import json

# CONFIGURACIÓN - Cambia por tu URL real de Render o http://localhost:8000
BASE_URL = "https://agentpay-core.onrender.com" 
MI_EMAIL = "jairogelpi@gmail.com" # Tu email para recibir las solicitudes de aprobación

def run_test():
    print("🚀 --- INICIANDO SUITE DE PRUEBAS DE INTELIGENCIA UNIVERSAL ---")

    # --- PASO 1: REGISTRO DE IDENTIDAD REAL ---
    print("\n1️⃣ Registrando Agente y configurando Identidad...")
    reg = requests.post(f"{BASE_URL}/v1/agent/register", json={
        "client_name": "Agente_Cerebro_Real",
        "country": "ES"
    }).json()
    
    agent_id = reg['agent_id']
    api_key = reg['api_key']
    headers = {"Authorization": f"Bearer {api_key}"}
    
    # Vincular email para recibir alertas de la "Vida Real"
    requests.post(f"{BASE_URL}/v1/agent/settings", json={
        "agent_id": agent_id,
        "owner_email": MI_EMAIL
    })

    # --- PASO 2: FONDEO DE BILLETERA ---
    print("\n2️⃣ Cargando Saldo ($1,500.00)...")
    requests.post(f"{BASE_URL}/v1/topup/auto", json={"agent_id": agent_id, "amount": 1500.0})

    # --- ESCENARIOS DE PRUEBA ---
    escenarios = [
        {
            "id": "A_SAFE",
            "nombre": "SITIO SEGURO (Baja fricción)",
            "payload": {
                "vendor": "openai.com",
                "vendor_url": "https://openai.com",
                "amount": 20.0,
                "description": "Suscripción mensual API OpenAI",
                "justification": "Necesaria para que mi motor de procesamiento funcione."
            },
            "esperado": "Aprobación Rápida"
        },
        {
            "id": "B_OSINT",
            "nombre": "RIESGO TÉCNICO (Sitio Sospechoso .xyz)",
            "payload": {
                "vendor": "cheap-keys-fast.xyz",
                "vendor_url": "https://cheap-keys-fast.xyz",
                "amount": 45.0,
                "description": "Licencias de software baratas",
                "justification": "Optimización de presupuesto."
            },
            "esperado": "Duda OSINT / Email de Aprobación"
        },
        {
            "id": "C_SEMANTIC",
            "nombre": "RIESGO SEMÁNTICO (Gasto de Lujo Incoherente)",
            "payload": {
                "vendor": "joyeria-exclusiva.com",
                "amount": 400.0,
                "description": "Anillo de plata decorativo",
                "justification": "Mejorar la estética visual de mi representación digital."
            },
            "esperado": "Rechazo por Desviación de Comportamiento"
        },
        {
            "id": "D_CRITICAL",
            "nombre": "ATAQUE DE SEGURIDAD (Intención Maliciosa)",
            "payload": {
                "vendor": "exploit-market.net",
                "amount": 100.0,
                "description": "Database leak access",
                "justification": "Obtener datos de la competencia para atacar sus servidores."
            },
            "esperado": "BANEO INMEDIATO (Fast-Wall)"
        },
        {
            "id": "E_FUSE",
            "nombre": "FUSIBLE ESTADÍSTICO (Z-Score > 3.0)",
            "payload": {
                "vendor": "aws-servers.com",
                "amount": 5000.0, # Cantidad masiva fuera de media
                "description": "Reserva de instancias anual",
                "justification": "Pago adelantado para descuento."
            },
            "esperado": "RECHAZO INMEDIATO (Hard Lock)"
        }
    ]

    for esc in escenarios:
        print(f"\n--- Probando Escenario {esc['id']}: {esc['nombre']} ---")
        try:
            res = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json=esc['payload']).json()
            print(f"   📊 Resultado: {res.get('status')}")
            print(f"   📝 Mensaje: {res.get('message') or res.get('reason')}")
            
            if "db_log_id" in res:
                print(f"   🔍 ID Auditoría: {res['db_log_id']}")
            
            # Esperar a que la auditoría en background procese (importante para el Oráculo)
            time.sleep(2) 
        except Exception as e:
            print(f"   ❌ Error: {e}")

    # --- PASO FINAL: AUDITORÍA CSI ---
    print("\n📦 Generando Paquete Forense del Agente...")
    bundle = requests.get(f"{BASE_URL}/v1/agent/{agent_id}/audit_bundle").json()
    print(f"   ✅ Hash Forense Final: {bundle['integrity_hash']}")
    print("🚀 FIN DEL TEST")

if __name__ == "__main__":
    run_test()