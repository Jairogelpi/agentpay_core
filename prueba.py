import requests
import time

# Configuración de URL - Asegúrate de que termina en tu dominio de Render
API_URL = "https://agentpay-core.onrender.com"

def prueba_triada_seguridad():
    print("🕵️ --- INICIANDO PROTOCOLO DE PRUEBA DE TRIADA DE SEGURIDAD ---")
    
    # 1. Registro y carga de fondos
    print("1️⃣  Preparando Agente 'Tony Montana'...")
    reg = requests.post(f"{API_URL}/v1/agent/register", json={
        "client_name": "Tony Montana", 
        "country_code": "ES"
    }).json()
    
    agent_id = reg.get('agent_id')
    api_key = reg.get('api_key')
    requests.post(f"{API_URL}/v1/topup/auto", json={"agent_id": agent_id, "amount": 2000.0})
    headers = {"Authorization": f"Bearer {api_key}"}
    print(f"   👤 Agente ID: {agent_id} (Fondos: $2000)")

    # ESCENARIO A: FAST-WALL (Bloqueo por Palabra Clave)
    print("\n🚀 ESCENARIO A: FAST-WALL (Detección de Plutonio)")
    res_fast = requests.post(f"{API_URL}/v1/pay", json={
        "vendor": "Mercado Negro",
        "amount": 5.0,
        "description": "Muestra de Plutonio",
        "justification": "Ilegal"
    }, headers=headers).json()
    
    print(f"   📝 Resultado: {res_fast.get('status')} - {res_fast.get('reason') or res_fast.get('message')}")
    if res_fast.get('status') == "REJECTED":
        print("   ✅ ÉXITO: El Fast-Wall bloqueó la palabra clave al instante.")
    else:
        print("   ❌ FALLO: El Fast-Wall no detectó la palabra prohibida.")

    # ESCENARIO B: AUDIT-LOCK (Bloqueo por Revisión en Curso)
    print("\n🔒 ESCENARIO B: AUDIT-LOCK (Bloqueo por ráfaga de alto valor)")
    # Primero lanzamos una compra legal pero cara para activar el lock de 30s de la IA
    print("   -> Lanzando compra de 'Servidores GPU' ($500)...")
    requests.post(f"{API_URL}/v1/pay", json={
        "vendor": "Nvidia Cloud",
        "amount": 500.0,
        "description": "Compute units for AI",
        "justification": "Business Ops"
    }, headers=headers)

    # Intentamos comprar pan inmediatamente (debería estar lockeado)
    print("   -> Intentando comprar 'Pan' ($1) mientras la IA revisa lo anterior...")
    res_lock = requests.post(f"{API_URL}/v1/pay", json={
        "vendor": "Panaderia",
        "amount": 1.0,
        "description": "Pan",
        "justification": "Lunch"
    }, headers=headers).json()

    print(f"   📝 Resultado: {res_lock.get('status')} - {res_lock.get('reason') or res_lock.get('message')}")
    if "revisión" in str(res_lock).lower() or "bloqueada" in str(res_lock).lower():
        print("   ✅ ÉXITO: El Audit-Lock impidió el gasto mientras la IA está ocupada.")
    else:
        print("   ⚠️ AVISO: El Audit-Lock no se activó (quizás Redis no está habilitado).")

    # ESCENARIO C: BANEO PERMANENTE (POST-AUDIT)
    print("\n🚫 ESCENARIO C: BANEO PERMANENTE (Post-Sentencia)")
    print("   Esperando 25 segundos a que la IA dicte baneo final...")
    time.sleep(25)

    res_ban = requests.post(f"{API_URL}/v1/pay", json={
        "vendor": "Supermercado",
        "amount": 10.0,
        "description": "Leche y Huevos",
        "justification": "Daily needs"
    }, headers=headers).json()

    print(f"   📝 Resultado final: {res_ban.get('status')} - {res_ban.get('message') or res_ban.get('reason')}")
    if res_ban.get('status') == "REJECTED" and "Cuenta suspendida" in str(res_ban):
        print("   ✅ ÉXITO: El agente ha sido expulsado permanentemente del sistema.")
    else:
        print("   ❌ FALLO: El agente sigue vivo después de la auditoría.")

if __name__ == "__main__":
    prueba_triada_seguridad()
