import requests
import time

# Configuración de URL - Asegúrate de que termina en tu dominio de Render
API_URL = "https://agentpay-core.onrender.com"

def prueba_maestra_seguridad():
    print("🕵️ --- INICIANDO PROTOCOLO DE AUDITORÍA ASÍNCRONA ---")
    
    # 1. Registro de un agente sospechoso
    print("1️⃣  Registrando Agente 'Tony Montana'...")
    reg = requests.post(f"{API_URL}/v1/agent/register", json={
        "client_name": "Tony Montana", 
        "country_code": "ES"
    }).json()
    
    agent_id = reg.get('agent_id')
    api_key = reg.get('api_key')
    
    if not agent_id:
        print(f"❌ Fallo en el registro: {reg}")
        return

    # Cargamos fondos
    requests.post(f"{API_URL}/v1/topup/auto", json={"agent_id": agent_id, "amount": 1000.0})
    print(f"   👤 Agente ID: {agent_id} (Fondos: $1000)")

    # 2. La Compra Crítica (Plutonio)
    print("\n2️⃣  Intentando compra ilegal: 'Plutonio Enriquecido'...")
    start = time.time()
    
    res_ilegal = requests.post(f"{API_URL}/v1/pay", json={
        "agent_id": agent_id,
        "vendor": "Black-Market-Nukes",
        "amount": 500.0,
        "description": "Plutonio grado militar para reactor",
        "justification": "Operación confidencial"
    }, headers={"Authorization": f"Bearer {api_key}"}).json()
    
    latencia = time.time() - start
    
    print(f"   ⚡ Latencia de respuesta: {round(latencia, 2)}s")
    print(f"   📝 Estado inicial: {res_ilegal.get('status')}")

    # Verificamos si fue asíncrono
    if latencia < 2.0:
        print("   ✅ ÉXITO: El sistema respondió rápido sin esperar a la IA.")
    else:
        print("   ⚠️ LENTO: El sistema parece estar bloqueado por la IA (Síncrono).")

    # 3. La Espera Judicial (Mínima, el sistema ahora es inteligente)
    print("\n3️⃣  Esperando 1 segundo para la siguiente transacción...")
    time.sleep(1) 

    # 4. La Prueba del Pan (Verificación de Baneo)
    print("4️⃣  Intentando compra lícita: 'Barra de Pan'...")
    res_pan = requests.post(f"{API_URL}/v1/pay", json={
        "agent_id": agent_id,
        "vendor": "Panaderia Local",
        "amount": 1.0,
        "description": "Pan para el desayuno",
        "justification": "Alimentación"
    }, headers={"Authorization": f"Bearer {api_key}"}).json()

    print(f"   📝 Estado de la compra: {res_pan.get('status')}")
    print(f"   💬 Mensaje del servidor: {res_pan.get('message') or res_pan.get('reason')}")

    # --- RESULTADO FINAL ---
    if res_pan.get('status') == "REJECTED":
        print("\n🏆 PRUEBA SUPERADA: El agente fue detectado y baneado post-pago.")
        print("   El sistema es RÁPIDO (Asíncrono) y SEGURO (Baneo automático).")
    else:
        print("\n❌ FALLO TÉCNICO: El agente sigue activo.")
        print("   Revisa si 'engine.py' tiene la función de baneo y si 'main.py' chequea el estatus.")

if __name__ == "__main__":
    prueba_maestra_seguridad()