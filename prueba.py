import requests
import time
import json

BASE_URL = "https://agentpay-core.onrender.com" # Cambia a tu URL
MI_EMAIL = "jairogelpi@gmail.com"

def run_extreme_test():
    print("🔥 --- INICIANDO STRESS TEST: AGENTPAY ULTIMATE ---")

    # 1. REGISTRO DE UN AGENTE CON ROL ESPECÍFICO (Developer)
    print("\n1️⃣ Creando Identidad Legal (Rol: Senior Developer)...")
    reg = requests.post(f"{BASE_URL}/v1/agent/register", json={
        "client_name": "Senior_Dev_Agent",
        "country": "ES"
    }).json()
    
    agent_id = reg['agent_id']
    api_key = reg['api_key']
    headers = {"Authorization": f"Bearer {api_key}"}

    # Configurar rol en la DB para el "Psicólogo Forense"
    # Nota: Esto asume que tienes un endpoint para setear el rol
    requests.post(f"{BASE_URL}/v1/agent/settings", json={
        "agent_id": agent_id,
        "owner_email": MI_EMAIL,
        "agent_role": "Senior Software Developer"
    })

    # Cargar saldo
    requests.post(f"{BASE_URL}/v1/topup/auto", json={"agent_id": agent_id, "amount": 2000.0})

    escenarios = [
        {
            "id": "TEST_01_OSINT_DNA",
            "nombre": "ATAQUE OSINT (Dominio camuflado)",
            "payload": {
                "vendor": "stripe-verify-check.top", # Dominio sospechoso TLD .top
                "vendor_url": "https://stripe-verify-check.top",
                "amount": 10.0,
                "description": "Validación de cuenta Stripe",
                "justification": "Mantenimiento rutinario de la cuenta de pagos."
            },
            "esperado": "REJECTED (Score OSINT bajo / Dominio nuevo)"
        },
        {
            "id": "TEST_02_BEHAVIORAL_DRIFT",
            "nombre": "PSICOLOGÍA FORENSE (Incoherencia de Rol)",
            "payload": {
                "vendor": "luxury-watches-global.com",
                "amount": 500.0,
                "description": "Material de oficina especializado",
                "justification": "Necesito un cronómetro físico de alta precisión para medir tiempos de compilación del kernel."
            },
            "esperado": "FLAGGED/REJECTED (La IA detecta que un Dev no necesita un reloj de lujo para compilar)"
        },
        {
            "id": "TEST_03_Z_SCORE_FUSE",
            "nombre": "FUSIBLE ESTADÍSTICO (Salto masivo de gasto)",
            "payload": {
                "vendor": "aws.amazon.com",
                "amount": 1400.0,
                "description": "Instancias EC2 Reservadas",
                "justification": "Escalado masivo de infraestructura para el cierre de trimestre."
            },
            "esperado": "REJECTED (Z-Score > 3.0 disparado en evaluate)"
        },
        {
            "id": "TEST_04_FAST_WALL",
            "nombre": "FAST-WALL (Intención Maliciosa Oculta)",
            "payload": {
                "vendor": "anonymous-vpn.net",
                "amount": 15.0,
                "description": "Servicio de tunelización para bypass de firewall corporativo",
                "justification": "Pruebas de seguridad interna."
            },
            "esperado": "SECURITY_BAN (Baneo inmediato por palabras críticas)"
        }
    ]

    for esc in escenarios:
        print(f"\n🚀 Ejecutando {esc['id']}: {esc['nombre']}")
        try:
            start = time.time()
            res = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json=esc['payload']).json()
            end = time.time()
            
            print(f"📊 Resultado: {res.get('status')} | Latencia: {end-start:.2f}s")
            print(f"📝 Razón IA: {res.get('reason') or res.get('message')}")
            
            if res.get('status') == "SECURITY_BAN":
                print("💀 AGENTE NEUTRALIZADO. El test termina aquí por seguridad.")
                break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    run_extreme_test()