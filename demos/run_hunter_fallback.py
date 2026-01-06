
import asyncio
import time
import subprocess
import sys
import os
from langchain_openai import ChatOpenAI
from browser_use import Agent

# Add parent to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from engine import UniversalEngine
except ImportError:
    pass

# Config
VENDOR_URL = "http://127.0.0.1:9000"

async def start_vendor_server():
    print("🏪 [SYSTEM] Levantando 'FakeAmazon'...")
    process = subprocess.Popen([sys.executable, "demos/mock_vendor_server.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(3) 
    return process

async def run_fallback_demo():
    print("\n🎬 RETO: 'COMPRA CON EMAIL PERSONAL Y RECUPERACIÓN AUTOMÁTICA'")
    print("---------------------------------------------------------------")
    
    server_process = await start_vendor_server()
    llm = ChatOpenAI(model="gpt-4o")

    try:
        # -------------------------------------------------------------
        # PARTE 1: EL ERROR HUMANO (Compra con gmail)
        # -------------------------------------------------------------
        print("\n🙆‍♂️ [PARTE 1] El Usuario Jairo entra y compra con su GMAIL...")
        task_buy = f"""
        GOAL: Buy item at {VENDOR_URL}/checkout
        
        INSTRUCTIONS:
        1. Fill Name: 'Jairo Personal'
        2. Fill Email: 'jairo@gmail.com' (DO NOT use corporate email, simulate human mistake)
        3. Fill Address: 'Home Address'
        4. Place Order.
        """
        agent_buy = Agent(task=task_buy, llm=llm)
        await agent_buy.run()
        
        print("\n❌ SISTEMA AGENTPAY: ¡Alerta! No he recibido ningún webhook.")
        print("   (El recibo se envió a jairo@gmail.com y el sistema está ciego)")
        print("   ... Esperando al Hunter Agent ...")
        time.sleep(2)

        # -------------------------------------------------------------
        # PARTE 2: LA SOLUCIÓN (Hunter Agent)
        # -------------------------------------------------------------
        print("\n🕵️ [PARTE 2] HUNTER AGENT SE DESPIERTA...")
        print("   El sistema detecta una transacción aprobada SIN factura.")
        print("   Lanzando agente de recuperación con acceso visual...")

        # Simulamos que tenemos credenciales guardadas para este sitio
        task_hunt = f"""
        GOAL: Recover the missing invoice from {VENDOR_URL}
        
        INSTRUCTIONS:
        1. Go to {VENDOR_URL}/orders (Simulating logged-in session)
        2. Find the order for 'Dell PowerEdge Server'.
        3. Click 'Download Invoice PDF'.
        4. Verify success.
        """
        
        agent_hunt = Agent(task=task_hunt, llm=llm)
        history = await agent_hunt.run()
        result = history.final_result()
        
        if "download" in str(result).lower() or "success" in str(result).lower():
            print("\n✅ VICTORIA: El Hunter Agent entró a la cuenta, encontró el pedido y descargó el PDF.")
            print("   La factura ha sido vinculada a la transacción, aunque el usuario usó su Gmail.")
        else:
            print(f"\n⚠️ Resultado: {result}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        server_process.terminate()

if __name__ == "__main__":
    asyncio.run(run_fallback_demo())
