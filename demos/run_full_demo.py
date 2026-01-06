
import asyncio
import time
import subprocess
import sys
import os
from playwright.async_api import async_playwright

# Add parent directory to path to import engine
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from engine import UniversalEngine
except ImportError:
    print("❌ Critical Error: Could not import 'engine'. Run this from agentpay_core root.")
    sys.exit(1)

# Config
VENDOR_URL = "http://127.0.0.1:9000"

async def start_vendor_server():
    print("🏪 [SYSTEM] Levantando 'FakeAmazon' en local...")
    process = subprocess.Popen([sys.executable, "demos/mock_vendor_server.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(3) 
    return process

# --- REAL ENGINE INITIALIZATION ---
print("⚙️  [SYSTEM] Inicializando Motor Real (AgentPay Engine)...")
engine = UniversalEngine()

def setup_real_agent():
    """Crea un agente real en la DB para la prueba."""
    import uuid
    agent_id = f"ag_DEMO_{uuid.uuid4().hex[:6]}"
    print(f"   👤 Creando Agente Real en DB: {agent_id}...")
    
    # Insertamos directamente en wallets para asegurar que existe con datos fiscales
    engine.db.table("wallets").insert({
        "agent_id": agent_id,
        "balance": 5000,
        "owner_name": "Demo User Real",
        "tax_id": "ES-B99999999",
        "status": "active"
    }).execute()
    
    return agent_id

async def scenario_1_buyer_agent(page, agent_id):
    print("\n🎬 ESCENARIO A: Agente Comprador (Email Flow)")
    print("---------------------------------------------")
    
    # 1. Navegar
    print(f"1. 🌍 Agente entra en: {VENDOR_URL}/checkout")
    await page.goto(f"{VENDOR_URL}/checkout")
    
    # 2. Pensar / Usar Herramientas (REAL)
    print("2. 🧠 Agente analiza el formulario y LLAMA al Engine Real...")
    
    # --- LLAMADA REAL A LA LÓGICA DE NEGOCIO ---
    print(f"   🛠️  [AGENT] Executing: engine.get_billing_profile('{agent_id}')")
    billing_data = engine.get_billing_profile(agent_id)
    
    if not billing_data:
        print("❌ ERROR: El Engine devolvió None. Fallo en la prueba real.")
        return

    print(f"   ⬇️  Data Real Recibida de DB: {billing_data}")

    # 3. Actuar
    print("3. ✍️  Agente rellena el formulario con datos corporativos...")
    await page.fill('input[name="name"]', billing_data["billing_name"])
    await page.fill('input[name="email"]', billing_data["billing_email"]) # <--- MAGIC HERE
    # Flatten address for simple demo form
    addr = billing_data["billing_address"]
    full_address = f"{addr['line1']}, {addr['city']}"
    await page.fill('input[name="address"]', full_address)
    
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
    
    # Setup Real Agent
    real_agent_id = setup_real_agent()
    
    try:
        async with async_playwright() as p:
            # Lanzamos navegador visible para el usuario (si tiene GUI, sino headless)
            # Para demo, headless=True es más seguro en entornos remotos, pero False mola más.
            # Pondremos True para asegurar compatibilidad.
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            await scenario_1_buyer_agent(page, real_agent_id)
            
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
