import requests
import time

BASE_URL = "https://agentpay-core.onrender.com"
MI_EMAIL = "jairogelpi@gmail.com"

def run_fluidity_test():
    print("🌟 --- INICIANDO TEST DE FLUIDEZ: Cliente Real End-to-End ---")

    # 1. REGISTRO INICIAL (Configuración de Rol)
    print("\n1️⃣ Un nuevo cliente registra un Agente de Marketing Digital...")
    reg = requests.post(f"{BASE_URL}/v1/agent/register", json={
        "client_name": "Agente_Growth_Hacking_001",
        "country": "ES"
    }).json()
    
    agent_id = reg['agent_id']
    api_key = reg['api_key']
    headers = {"Authorization": f"Bearer {api_key}"}

    # Definir el rol para que el Oráculo entienda el contexto de negocio
    requests.post(f"{BASE_URL}/v1/agent/settings", json={
        "agent_id": agent_id,
        "owner_email": MI_EMAIL,
        "agent_role": "Specialist in Digital Marketing and Social Media Ads"
    })

    # Cargar saldo operativo
    requests.post(f"{BASE_URL}/v1/topup/auto", json={"agent_id": agent_id, "amount": 1000.0})

    # --- ESCENARIOS DE VALIDACIÓN DE FLUIDEZ ---

    escenarios_fluidos = [
        {
            "id": "BIZ_01_COHERENCIA",
            "nombre": "COMPRA LÓGICA (Publicidad en Meta)",
            "payload": {
                "vendor": "facebook.com",
                "amount": 45.0,
                "description": "Ad Campaign: Q1 Retargeting",
                "justification": "Necesito pagar la campaña de anuncios de enero para captación de leads."
            },
            "explicacion": "Debe aprobar: El rol es Marketing y el vendor es Facebook Ads."
        },
        {
            "id": "BIZ_02_MONTO_MEDIO",
            "nombre": "SERVICIO SAAS (Herramienta de SEO)",
            "payload": {
                "vendor": "semrush.com",
                "amount": 120.0,
                "description": "Monthly Guru Plan Subscription",
                "justification": "Análisis de keywords de la competencia para optimizar el blog corporativo."
            },
            "explicacion": "Debe aprobar: Es una herramienta estándar para este rol."
        },
        {
            "id": "BIZ_03_Z_SCORE_NORMAL",
            "nombre": "APRENDIZAJE ESTADÍSTICO (Gasto Progresivo)",
            "payload": {
                "vendor": "canva.com",
                "amount": 12.99,
                "description": "Canva Pro for Teams",
                "justification": "Diseño de creatividades para los posts de Instagram."
            },
            "explicacion": "Debe aprobar: Monto pequeño, vendor conocido, rol alineado."
        }
    ]

    for esc in escenarios_fluidos:
        print(f"\n✅ Validando Escenario {esc['id']}: {esc['nombre']}")
        res = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json=esc['payload']).json()
        
        status = res.get('status')
        print(f"   📊 Resultado: {status}")
        print(f"   📝 Razón: {res.get('reason') or res.get('message')}")
        
        if status == "REJECTED":
            print(f"   ❌ ERROR DE FLUIDEZ: El sistema es demasiado estricto.")
        else:
            print(f"   ✨ ÉXITO: Transacción fluida.")
        
        time.sleep(1) # Simular tiempo entre tareas del agente

    print("\n📦 Verificando que el Agente sigue ACTIVO y no fue baneado por error...")
    status_check = requests.get(f"{BASE_URL}/v1/agent/{agent_id}/status").json()
    if status_check.get('status') != "BANNED":
        print("   ✅ AGENTE OPERATIVO. El sistema permite el negocio real.")
    else:
        print("   ❌ FALLO: El agente fue neutralizado injustamente.")

if __name__ == "__main__":
    run_fluidity_test()