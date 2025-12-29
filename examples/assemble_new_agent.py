
import requests
import time
import os

HOST = "https://agentpay-core.onrender.com"
# HOST = "http://localhost:8000"

def log(emoji, msg): print(f"{emoji} {msg}")

def run_assembly():
    print("\n" + "🧱"*20)
    print("  AGENTPAY ASSEMBLY BUILDER")
    print("  Ensambla tu IA en 60 segundos")
    print("🧱"*20 + "\n")

    # 1. ENSAMBLAR: Registro de Identidad
    agent_name = input("📝 1. Nombre de tu Agente (ej: 'SEO Optimizer Bot'): ")
    log("🚀", f"Registrando '{agent_name}' en la infraestructura AgentPay...")
    
    r = requests.post(f"{HOST}/v1/agent/register", json={"client_name": agent_name})
    if r.status_code != 200:
        log("❌", "Error en el registro.")
        return
    
    data = r.json()
    api_key = data.get('api_key')
    log("✅", f"¡Ensamblado! Tu API KEY es: {api_key}")
    log("📊", f"Tu Dashboard está listo en: {data.get('dashboard_url')}")

    # 2. FONDEAR: Obtener Link de Recarga
    print("\n" + "-"*40)
    amount = input("💰 2. ¿Cuánto saldo quieres meter para empezar? ($): ")
    log("💳", f"Generando link de recarga para {api_key}...")
    
    r = requests.post(f"{HOST}/v1/topup/create", json={"agent_id": api_key, "amount": float(amount)})
    if r.status_code == 200:
        topup_url = r.json().get('url')
        log("🔗", f"LINK DE PAGO REAL: {topup_url}")
        log("💡", "Paga en ese link y el dinero se moverá solo a tu balance de Issuing.")
    
    # 3. OPERAR: Ejemplo de integración en el código de tu IA
    print("\n" + "-"*40)
    log("🤖", "3. INTEGRACIÓN EN TU CÓDIGO:")
    print(f"""
    # En el código de tu IA, solo tienes que hacer esto:
    
    import requests
    
    response = requests.post("{HOST}/v1/pay", json={{
        "agent_id": "{api_key}",
        "vendor": "openai.com",
        "amount": 5.00,
        "description": "API Credits for {agent_name}",
        "justification": "Necesario para ejecutar la tarea de optimización"
    }})
    
    if response.json().get('authorized'):
        card = response.json().get('card_details')
        print(f"¡Pagado! Usa la tarjeta: {{card['number']}}")
    """)

    print("\n" + "🎉"*20)
    print("  ¡TU AGENTE YA TIENE PODERES FINANCIEROS!")
    print("🎉"*20 + "\n")

if __name__ == "__main__":
    run_assembly()
