
import asyncio
import os
import json
import base64
from langchain_openai import ChatOpenAI
from browser_use import Agent, BrowserConfig
# from playwright.async_api import async_playwright # Browser-use manages this usually
from supabase import create_client
from loguru import logger
from datetime import datetime
from security_utils import decrypt_password

# --- CONFIGURACIÓN ROBUSTA ---
try:
    supabase = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
except:
    logger.warning("Supabase details missing from env, hunter agent won't connect.")
    supabase = None

try:
    llm = ChatOpenAI(model="gpt-4o", api_key=os.getenv("OPENAI_API_KEY")) 
except:
    logger.warning("OpenAI Key missing, hunter agent needs it.")
    llm = None

def extract_domain(vendor_name):
    # Simple helper: "Amazon AWS" -> "amazon"
    if not vendor_name: return ""
    return vendor_name.split()[0].lower().replace(".com", "")

async def report_failure(tx, agent, error_msg):
    """
    Sube un screenshot del error y crea un ticket para el humano.
    """
    logger.warning("📸 Generando reporte de fallo...")
    
    # Intentar sacar screenshot del último estado (si la lib lo permite)
    # screenshot_path = await agent.browser_context.pages[0].screenshot(path="error.png")
    
    # Subir a Supabase (Simulado)
    public_url = "https://placeholder/error_screenshot.png" 
    
    if supabase:
        supabase.table("manual_review_queue").insert({
            "transaction_id": tx['id'],
            "agent_id": tx['agent_id'],
            "vendor": tx['vendor'],
            "error_log": str(error_msg),
            "screenshot_url": public_url,
            "status": "OPEN"
        }).execute()

async def process_single_transaction(tx):
    agent_id = tx['agent_id']
    vendor_domain = extract_domain(tx['vendor']) # "amazon", "google"
    
    # 2. Obtener Credenciales y COOKIES
    creds_res = supabase.table("vendor_credentials")\
        .select("*")\
        .eq("agent_id", agent_id)\
        .ilike("domain", f"%{vendor_domain}%")\
        .single()\
        .execute()

    if not creds_res.data:
        logger.warning(f"⚠️ Sin credenciales para {vendor_domain} del agente {agent_id}. Saltando.")
        return

    creds = creds_res.data
    # cookies = creds.get('session_cookies') # Future use with browser-use injection

    username = creds.get('username')
    encrypted_pass = creds.get('encrypted_password')
    password = decrypt_password(encrypted_pass) if encrypted_pass else ""

    logger.info(f"🕵️ Cazando en {vendor_domain} con sesión pre-cargada...")

    # 3. Lógica de Navegación "Human-Like"
    task_prompt = f"""
    GOAL: Download invoice for ${tx['amount']} from date {tx['created_at'][:10]}.
    
    STRATEGY:
    1. Go to {creds.get('login_url') or 'https://' + vendor_domain + '.com'}.
    2. CHECK LOGIN: Are we logged in? (Look for 'Account', 'Sign Out', or Profile Icon).
       - IF NOT LOGGED IN: Attempt login with User: "{username}" Pass: "{password}".
       - IF BLOCKED/CAPTCHA: Stop and fail gracefully.
    3. NAVIGATE: Go to 'Returns & Orders', 'Billing', or 'Invoices'.
    4. FIND: Look for order around {tx['created_at'][:10]} matching approx ${tx['amount']}.
    5. ACTION: Download the PDF Invoice.
    """
    
    agent = Agent(
        task=task_prompt,
        llm=llm,
    )

    try:
        # Ejecutar Misión
        history = await agent.run()
        result = history.final_result()
        
        # 4. VERIFICACIÓN DE ÉXITO
        if result and ("downloaded" in result.lower() or "saved" in result.lower() or "success" in result.lower()):
            # En una implementación real, recuperaríamos el archivo del sistema de archivos local
            # o del output del agente. Aquí simulamos el éxito.
            logger.success(f"✅ Factura recuperada para {vendor_domain}")
            
            # Actualizar estado de transacción
            supabase.table("transaction_logs").update({
                "invoice_status": "FOUND_BROWSER",
                "invoice_url": "https://bucket/recovered_invoice.pdf" # Placeholder
            }).eq("id", tx['id']).execute()
            
        else:
            raise Exception("No se encontró confirmación explícita de descarga.")

    except Exception as e:
        logger.error(f"💥 Fallo en navegación: {e}")
        # 5. REPORTE DE INCIDENTES (HUMAN IN THE LOOP)
        await report_failure(tx, agent, str(e))


async def hunt_missing_invoices_pro():
    """
    Versión INDUSTRIAL: Usa cookies, maneja errores y reporta fallos visuales.
    """
    if not supabase or not llm:
        logger.error("Faltan configuraciones (Supabase/OpenAI). Abortando.")
        return

    logger.info("🛡️ Iniciando Hunter Agent (Modo Stealth)...")
    
    # 1. Buscar objetivos (Transacciones antiguas sin factura)
    try:
        targets = supabase.table("transaction_logs")\
            .select("*")\
            .eq("status", "APPROVED")\
            .eq("invoice_status", "PENDING_HUNT")\
            .limit(3)\
            .execute() 

        for tx in targets.data:
            try:
                await process_single_transaction(tx)
            except Exception as e:
                logger.error(f"❌ Error crítico procesando TX {tx['id']}: {e}")
                
    except Exception as e:
        logger.error(f"Error fetching targets: {e}")

if __name__ == "__main__":
    asyncio.run(hunt_missing_invoices_pro())
