
import asyncio
import time
import subprocess
import sys
import os
from playwright.async_api import async_playwright

# Config
VENDOR_URL = "http://127.0.0.1:9000"

async def start_vendor_server():
    print("🏪 [SYSTEM] Levantando 'FakeAmazon' en local...")
    # Ejecutamos el servidor como subproceso
    process = subprocess.Popen([sys.executable, "demos/mock_vendor_server.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(3) # Wait for startup
    return process

# --- SIMULACIÓN DE LA HERRAMIENTA 'get_billing_info' ---
def get_billing_info_tool(agent_id):
    print("   🛠️  [AGENT] Calling Tool: get_billing_info()...")
    return {
        "billing_name": "Jairo (AgentPay AI)",
        "billing_email": f"{agent_id}@inbound.agentpay.io",
        "billing_address": "Tech District 1, Madrid"
    }

async def scenario_1_buyer_agent(page):
    print("\n🎬 ESCENARIO A: Agente Comprador (Email Flow)")
    print("---------------------------------------------")
    
    # 1. Navegar
    print(f"1. 🌍 Agente entra en: {VENDOR_URL}/checkout")
    await page.goto(f"{VENDOR_URL}/checkout")
    
    # 2. Pensar / Usar Herramientas
    print("2. 🧠 Agente analiza el formulario...")
    # Simula el LLM viendo los campos 'name', 'email', 'address'
    agent_id = "ag_8888"
    billing_data = get_billing_info_tool(agent_id)
    
    # 3. Actuar
    print("3. ✍️  Agente rellena el formulario con datos corporativos...")
    await page.fill('input[name="name"]', billing_data["billing_name"])
    await page.fill('input[name="email"]', billing_data["billing_email"]) # <--- MAGIC HERE
    await page.fill('input[name="address"]', billing_data["billing_address"])
    
    print(f"   > Usando Email Mágico: {billing_data['billing_email']}")
    
    # 4. Comprar
    print("4. 🛒 Agente hace clic en 'Place Order'")
    await page.click('button')
    
    # 5. Verificar Resultado
    await page.wait_for_selector('h1')
    content = await page.content()
    
    if "Order Placed Successfully" in content and billing_data["billing_email"] in content:
        print("✅ ÉXITO: El vendedor confirmó envío al email corporativo.")
    else:
        print("❌ FALLO: Algo salió mal en la compra.")

async def scenario_2_hunter_agent(page):
    print("\n🎬 ESCENARIO B: Agente Cazador (Hunter Flow - Sin Email)")
    print("-----------------------------------------------------")
    print("ℹ️  Supongamos que el email falló. Pasaron 24h. El Hunter Agent se despierta.")
    
    # 1. Navegar a Historial
    print(f"1. 🕵️  Hunter entra en: {VENDOR_URL}/orders")
    await page.goto(f"{VENDOR_URL}/orders")
    
    # 2. Buscar Factura
    print("2. 👁️  Hunter escanea la página buscando 'Invoice' o 'Receipt'...")
    # Simula LLM finding xpath
    invoice_link = await page.query_selector("text=Download Invoice PDF")
    
    if invoice_link:
        print("   -> ¡Encontrado enlace de factura!")
        
        # 3. Descargar
        print("3. ⬇️  Hunter descarga el archivo...")
        async with page.expect_download() as download_info:
            await invoice_link.click()
            
        download = await download_info.value
        path = await download.path()
        print(f"✅ ÉXITO: Factura descargada y guardada temporalmente en: {path}")
        print("   (El sistema ahora subiría esto a Supabase y cerraría el ticket).")
        
    else:
        print("❌ FALLO: No se encontró botón de descarga.")

async def run_simulation():
    # Start Server
    server_process = await start_vendor_server()
    
    try:
        async with async_playwright() as p:
            # Lanzamos navegador visible para el usuario (si tiene GUI, sino headless)
            # Para demo, headless=True es más seguro en entornos remotos, pero False mola más.
            # Pondremos True para asegurar compatibilidad.
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            await scenario_1_buyer_agent(page)
            
            # Pausa dramática
            time.sleep(2)
            
            await scenario_2_hunter_agent(page)
            
            await browser.close()
            
    except Exception as e:
        print(f"💥 Error en simulación: {e}")
    finally:
        print("\n🛑 Apagando servidor FakeAmazon...")
        server_process.terminate()

if __name__ == "__main__":
    asyncio.run(run_simulation())
