
import asyncio
import os
from langchain_openai import ChatOpenAI
from browser_use import Agent
# Simulación de herramientas MCP (En la vida real, se conectan al servidor MCP)
import json

# ==============================================================================
# 1. LA "PRIMERA DIRECTIVA" (SYSTEM PROMPT)
# ==============================================================================
# Aquí es donde "enseñamos" al Agente a saber cuándo y cómo usar la información.
# Esto se inyecta en la configuración de cualquier Agente que use AgentPay.

AGENT_PRIME_DIRECTIVE = """
YOU ARE A CORPORATE BUYING AGENT POWERED BY AGENTPAY.

CORE PROTOCOL FOR CHECKOUT & BILLING:
1. NEVER use personal or random addresses.
2. WHEN the website asks for "Billing Details" (Email, Name, Address, VAT):
   -> YOU MUST CALL tool `get_billing_info()`.
   -> FILL the form using EXACTLY the data returned by the tool.
   -> SPECIFICALLY, use the 'billing_email' (e.g., ag_X@inbound.agentpay.io) to ensure the invoice is captured.
   
3. IF you cannot enter the 'billing_email' (e.g. site requires phone verification on email):
   -> Use the tool `get_billing_info` to check if there is a backup instruction.
   -> LOG a warning.

4. AFTER PURCHASE:
   -> If there is a "Download Invoice" button, CLICK IT and save the file.
   -> If there is no download button, verify that the email sent to 'billing_email' will contain it.
"""

# ==============================================================================
# 2. SIMULACIÓN DEL AGENTE COMPRADOR
# ==============================================================================

async def run_proactive_buying_mission():
    print("🤖 Iniciando Agente de Compras con Protocolo AgentPay...")
    
    # Imaginemos que el Agente está en Amazon comprando un servidor
    task_description = """
    GOAL: Buy a 'Dell PowerEdge Server' on dell.com for $1200.
    
    CURRENT STATE: You are at the Checkout Page. 
    The site is asking for: "Billing Information".
    """
    
    # Instanciamos el LLM (El Cerebro)
    llm = ChatOpenAI(model="gpt-4o")
    
    # Creamos el Agente con la Directiva Maestra
    agent = Agent(
        task=task_description,
        llm=llm,
        system_prompt=AGENT_PRIME_DIRECTIVE, # <--- AQUÍ ESTÁ LA MAGIA
    )
    
    print("\n🧠 Pensamiento del Agente:")
    print("   1. Detecto que estoy en Checkout.")
    print("   2. Me piden 'Billing Information'.")
    print("   3. Mi Protocolo dice: 'CALL get_billing_info()'.")
    
    # --- SIMULACIÓN DE LA LLAMADA A LA HERRAMIENTA ---
    # En la realidad, el Browser-Use Agent ejecutaría esto automáticamente.
    print("\n🛠️ [TOOL CALL] get_billing_info()")
    billing_data = {
        "billing_name": "Jairo (AgentPay)",
        "billing_email": "ag_12345@inbound.agentpay.io",
        "billing_address": {"line1": "Calle Innovación 1", "city": "Madrid", "postal_code": "28001", "country": "ES"},
        "vat_number": "ES-B12345678"
    }
    print(f"   ⬇️ Recibido: {json.dumps(billing_data, indent=2)}")
    
    print("\n🤖 Acción del Agente:")
    print(f"   > Escribiendo en 'Email': {billing_data['billing_email']}")
    print(f"   > Escribiendo en 'Nombre': {billing_data['billing_name']}")
    print("   > Click en 'Confirmar Compra'")
    
    print("\n✅ RESULTADO: La factura se enviará a 'ag_12345@inbound.agentpay.io'.")
    print("   AgentPay interceptará el email, leerá el PDF y conciliará la transacción.")
    print("   Zero Touch. Zero Human Effort.")

if __name__ == "__main__":
    asyncio.run(run_proactive_buying_mission())
