import requests
import time
import json
import sys

# --- CONFIGURACIÓN ---
BASE_URL = "https://agentpay-core.onrender.com" 

# Colores
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

def print_step(msg):
    print(f"\n{CYAN}➤ {msg}{RESET}")

def run_test():
    print(f"{GREEN}🧠 INICIANDO DIAGNÓSTICO DEL SISTEMA (DEBUG MODE){RESET}")
    print(f"📡 Conectando a: {BASE_URL}\n")

    # ---------------------------------------------------------
    # PASO 1: CREAR AGENTE (CON CAPTURA DE ERROR)
    # ---------------------------------------------------------
    print_step("Creando Agente de Prueba...")
    
    reg_payload = {
        "client_name": "Neo Debugger",
        "country_code": "US",
        "agent_role": "Software Engineer"
    }

    try:
        res = requests.post(f"{BASE_URL}/v1/agent/register", json=reg_payload)
        
        # Intentamos leer el JSON
        try:
            data = res.json()
        except:
            print(f"{RED}❌ El servidor no devolvió JSON válido.{RESET}")
            print(f"Respuesta cruda: {res.text}")
            return

        # VERIFICACIÓN DE ERROR INTERNO
        if res.status_code != 200 or data.get("status") == "ERROR":
            print(f"{RED}❌ FALLO CRÍTICO AL CREAR AGENTE.{RESET}")
            print(f"👉 EL SERVIDOR DIJO: {YELLOW}{data.get('message')}{RESET}")
            print("-" * 40)
            print("Causas probables:")
            print("1. STRIPE_SECRET_KEY no es válida o falta en Render.")
            print("2. SUPABASE_URL / SUPABASE_KEY faltan o son incorrectas.")
            print("3. Tu cuenta de Stripe no tiene activadas las capacidades 'transfers' o 'issuing'.")
            return

        agent_id = data["agent_id"]
        api_key = data["api_key"]
        
        print(f"   ✅ Agente Creado: {agent_id}")
        
    except Exception as e:
        print(f"{RED}❌ Error de conexión fatal: {e}{RESET}")
        return

    # Headers
    headers = {"Authorization": f"Bearer {api_key}"}

    # ---------------------------------------------------------
    # PASO 2: INTENTAR OPERAR (Si llegamos aquí)
    # ---------------------------------------------------------
    print_step("Prueba de Fuego: Compra con IA")
    
    tx_payload = {
        "vendor": "Test Vendor AI",
        "amount": 10.00,
        "description": "System Diagnostics",
        "justification": "Testing AI Guard"
    }
    
    # Recarga rápida (intento)
    requests.post(f"{BASE_URL}/v1/topup/auto", json={"amount": 100.0}, headers=headers)
    
    start_t = time.time()
    tx_res = requests.post(f"{BASE_URL}/v1/pay", json=tx_payload, headers=headers)
    duration = time.time() - start_t
    
    try:
        tx_data = tx_res.json()
        status = tx_data.get("status")
        reason = tx_data.get("reason") or tx_data.get("message")
        
        print(f"   ⏱️ Tiempo: {duration:.2f}s")
        print(f"   📊 Estado: {GREEN if status == 'APPROVED' else RED}{status}{RESET}")
        print(f"   🧠 Razón:  {reason}")
        
        if "RAG" in str(reason) or "History" in str(reason):
            print(f"\n{GREEN}🎉 ¡GOD MODE ACTIVO! La memoria RAG está funcionando.{RESET}")
            
    except:
        print(f"   ⚠️ Respuesta cruda: {tx_res.text}")

if __name__ == "__main__":
    run_test()