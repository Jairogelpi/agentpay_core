import requests
import time

# Configura tu URL de producción en Render
API_URL = "https://agentpay-core.onrender.com"

def prueba_caos_financiero():
    print("🌪️ --- TEST DE CAOS: INTEGRIDAD DE DATOS ---")
    
    # 1. Preparar Agente con saldo exacto
    print("1️⃣  Registrando Agente para prueba de estrés...")
    reg = requests.post(f"{API_URL}/v1/agent/register", json={
        "client_name": "Caos Test User", 
        "country_code": "ES"
    }).json()
    
    agent_id = reg.get('agent_id')
    api_key = reg.get('api_key')
    
    if not agent_id:
        print(f"❌ Error en registro: {reg}")
        return

    saldo_inicial = 100.0
    requests.post(f"{API_URL}/v1/topup/auto", json={"agent_id": agent_id, "amount": saldo_inicial})
    print(f"   👤 Agente: {agent_id} | Saldo inicial: ${saldo_inicial}")

    # 2. EL ATAQUE: Transacción "Zombi"
    # Forzamos un timeout muy corto para que la petición se corte mientras el servidor trabaja.
    print("\n2️⃣  Lanzando transacción y forzando desconexión súbita...")
    try:
        requests.post(f"{API_URL}/v1/pay", json={
            "agent_id": agent_id,
            "vendor": "Chaos-Vendor-Store",
            "amount": 50.0,
            "description": "Pago Crítico de Supervivencia",
            "justification": "Test de Resiliencia Atómica"
        }, headers={"Authorization": f"Bearer {api_key}"}, timeout=0.5) 
    except requests.exceptions.Timeout:
        print("   ⚡ Conexión cortada por el cliente (Simulación de fallo de red exitosa).")
    except Exception as e:
        print(f"   ℹ️  La conexión se cerró: {e}")

    # 3. VERIFICACIÓN DE INTEGRIDAD
    print("\n3️⃣  Auditando estado tras el desastre...")
    time.sleep(5) # Esperamos a que el servidor termine su proceso interno
    
    # Consultamos saldo y logs
    status = requests.post(f"{API_URL}/v1/agent/status", json={"agent_id": agent_id}).json()
    saldo_final = float(status['finance']['balance'])
    
    # Obtenemos el bundle de auditoría para ver los logs reales
    logs_res = requests.get(f"{API_URL}/v1/agent/{agent_id}/audit_bundle").json()
    history = logs_res.get('financial_history', [])
    tx_registrada = any("Chaos-Vendor-Store" in str(tx.get('vendor')) for tx in history)

    print(f"\n📊 RESULTADO FORENSE:")
    print(f"   💰 Saldo Final: ${saldo_final}")
    print(f"   📝 ¿Transacción en el log?: {'SÍ' if tx_registrada else 'NO'}")

    # Lógica de Oro de Integridad Bancaria:
    # 1. Si el saldo bajó, el log DEBE existir.
    # 2. Si el saldo no bajó, el log NO DEBE existir.
    
    corrupcion = False
    if saldo_final < 100.0 and not tx_registrada:
        print("❌ ERROR: ¡Dinero fantasma! Se descontó saldo pero no hay registro del gasto.")
        corrupcion = True
    elif saldo_final == 100.0 and tx_registrada:
        print("❌ ERROR: ¡Log huérfano! Hay un registro de gasto pero no se descontó dinero.")
        corrupcion = True
        
    if not corrupcion:
        print("\n✅ PRUEBA SUPERADA: El sistema es atómico. Los datos son consistentes.")
    else:
        print("\n⚠️ ALERTA: Se ha detectado una inconsistencia de datos (Fallo de atomicidad).")

if __name__ == "__main__":
    prueba_caos_financiero()