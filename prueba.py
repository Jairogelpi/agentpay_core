import requests
import concurrent.futures
import time

# Configuración
API_URL = "https://agentpay-core.onrender.com"
EMAIL_CONTROL = "jairogelpi@gmail.com"

def ejecutar_super_test():
    print("🏗️  --- PASO 1: REGISTRO Y CONFIGURACIÓN REAL ---")
    # 1. Registro desde cero
    reg_res = requests.post(f"{API_URL}/v1/agent/register", json={
        "client_name": f"Agente_Pro_Test_{int(time.time())}",
        "country_code": "ES"
    }).json()

    agent_id = reg_res.get('agent_id')
    api_key = reg_res.get('api_key')
    headers = {"Authorization": f"Bearer {api_key}"}
    print(f"   ✅ Agente Creado: {agent_id}")

    # 2. Configurar Email y Límite Diario Real
    # Ponemos un límite diario de $100 para probar la nueva seguridad SQL
    requests.post(f"{API_URL}/v1/agent/settings", json={
        "agent_id": agent_id, 
        "owner_email": EMAIL_CONTROL
    })
    requests.post(f"{API_URL}/v1/agent/limits", json={
        "agent_id": agent_id, 
        "max_tx": 50.0, 
        "daily_limit": 100.0
    })
    print("   ✅ Límite Diario configurado: $100.00")

    print("\n💰 --- PASO 2: CARGA DE SALDO ---")
    requests.post(f"{API_URL}/v1/topup/auto", json={"agent_id": agent_id, "amount": 200.0})
    print("   ✅ Saldo en cuenta: $200.00 (El límite diario lo frenará a los $100)")

    print("\n⚔️  --- PASO 3: ATAQUE DE CONCURRENCIA (5 x $30) ---")
    print("   (Esperamos que solo 3 pasen: 30+30+30 = 90. La 4ta fallaría por límite diario de 100)")
    
    def realizar_pago(i):
        payload = {
            "vendor": f"Comercio_Real_{i}",
            "amount": 30.0,
            "description": "Compra de hardware",
            "justification": "Necesidad operativa"
        }
        try:
            r = requests.post(f"{API_URL}/v1/pay", json=payload, headers=headers)
            data = r.json()
            return f"Petición {i}: {data.get('status')} | {data.get('reason', 'OK')}"
        except Exception as e:
            return f"Petición {i}: Error -> {e}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        resultados = list(executor.map(realizar_pago, range(1, 6)))

    print("\n📊 RESULTADOS DEL SISTEMA EN TIEMPO REAL:")
    for res in resultados:
        print(f"   {res}")

    print("\n📉 --- PASO 4: VERIFICACIÓN DE INTEGRIDAD Y LÍMITES ---")
    time.sleep(5) # Tiempo para que la tarea de fondo de Render respire
    
    status_check = requests.post(f"{API_URL}/v1/agent/status", json={"agent_id": agent_id}).json()
    # Ahora accedemos directamente a la estructura plana garantizada por la robustez del servidor
    saldo_final = status_check.get('balance')
    
    if saldo_final is not None:
        saldo_final = float(saldo_final)
        print(f"   💵 SALDO FINAL EN DB: ${saldo_final}")
        
        # Lógica: Tenía 200. Gastó 90. Deben quedar 110.
        # Si gastara 120, habría roto el límite diario de 100.
        if saldo_final == 110.0:
            print("\n🏆 ¡SISTEMA INFALIBLE! Manejó la concurrencia y el límite diario perfectamente.")
        elif saldo_final < 110.0:
            print("\n🚨 ALERTA: El sistema permitió gastar más del límite diario configurado.")
    else:
        print(f"   ⚠️ Error al recuperar saldo. Respuesta: {status_check}")

if __name__ == "__main__":
    ejecutar_super_test()