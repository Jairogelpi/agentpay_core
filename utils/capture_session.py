from playwright.sync_api import sync_playwright
import json
import os
from supabase import create_client

# Conexión DB
try:
    supabase = create_client(os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY"))
except:
    print("Warning: SUPABASE_URL or KEY not set.")

def capture_session(agent_id, vendor_url, vendor_domain_key):
    """
    Abre un navegador REAL (con cabeza), deja que el humano se loguee,
    y cuando cierra, roba las cookies y las guarda en la nube.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False) # SE VE EL NAVEGADOR
        context = browser.new_context()
        page = context.new_page()
        
        print(f"🌍 Abriendo {vendor_url}...")
        try:
            page.goto(vendor_url)
        except Exception as e:
            print(f"Error loading page: {e}")
        
        print("⌨️  POR FAVOR, LOGUÉATE MANUALMENTE (Pon user, pass, 2FA SMS...).")
        print("🛑 Cierra la ventana del navegador cuando veas tu panel de usuario.")
        
        # Esperar a que el usuario cierre la página (manera simple de esperar)
        try:
            page.wait_for_event("close", timeout=0) # Espera infinita
        except:
            pass # El usuario cerró
            
        # CAPTURAR COOKIES
        cookies = context.cookies()
        print(f"🍪 Capturadas {len(cookies)} cookies. Guardando en la Nube...")
        
        # Guardar en Supabase
        if supabase:
            supabase.table("vendor_credentials").upsert({
                "agent_id": agent_id,
                "domain": vendor_domain_key,
                "session_cookies": cookies, # JSONB Mágico
                "last_login_success": "now()"
            }, on_conflict="agent_id, domain").execute()
            print("✅ Sesión guardada. El bot ahora puede entrar sin password.")
        else:
            print("❌ No se pudo guardar: Conexión a Supabase fallida.")

if __name__ == "__main__":
    # Ejemplo de uso interactivo si se corre directo
    import sys
    if len(sys.argv) > 3:
        capture_session(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print("Uso: python capture_session.py <agent_id> <vendor_url> <domain_key>")
        print("Ej: python capture_session.py ag_123 https://amazon.com amazon")
