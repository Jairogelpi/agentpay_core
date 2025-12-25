import requests

# --- CONFIGURACIÓN ---
# 1. Pon aquí TU URL de Render (sin barra al final)
API_URL = "https://agentpay-core.onrender.com" 

print("🚀 INICIANDO SIMULACIÓN DE CLIENTE SAAS...")

# 1. REGISTRO (El cliente crea su cuenta)
print("\n[1] Intentando registrar 'Startup IA Innovadora'...")
try:
    resp = requests.post(f"{API_URL}/v1/register", json={
        "client_name": "Startup IA Innovadora"
    })
    
    if resp.status_code != 200:
        print("❌ Error en registro:", resp.text)
        exit()
        
    data = resp.json()
    mi_key = data['data']['api_key']
    mi_id = data['data']['agent_id']
    
    print(f"✅ ¡CUENTA CREADA!")
    print(f"   -> ID Cliente: {mi_id}")
    print(f"   -> API Key recibida: {mi_key}")

except Exception as e:
    print(f"❌ Error de conexión: {e}")
    exit()

# 2. INTENTO DE PAGO (Usando la llave recién creada)
print(f"\n[2] Intentando pagar $15.00 a 'proveedor-desconocido.com' con la nueva llave...")

headers = {
    "X-API-KEY": mi_key,  # <--- Usamos la llave que nos acaba de dar el servidor
    "Content-Type": "application/json"
}

payload = {
    "vendor": "proveedor-desconocido.com",
    "amount": 15.00,
    "description": "Prueba de integración automática"
}

resp_pago = requests.post(f"{API_URL}/v1/pay", json=payload, headers=headers)

print("\n[3] RESPUESTA DEL SERVIDOR:")
print(resp_pago.json())

print("\n------------------------------------------------")
if "approval_link" in resp_pago.text:
    print("🎯 RESULTADO ESPERADO: El sistema pidió aprobación porque el proveedor es nuevo.")
    print("   El enlace debería estar arriba en el JSON.")
else:
    print("🤔 RESULTADO: Revisa el mensaje arriba.")