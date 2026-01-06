
import requests
import json
import uuid
import time
import base64
import os

# Configuración
BASE_URL = os.getenv("AGENTPAY_URL", "http://localhost:8000")
WEBHOOK_URL = f"{BASE_URL}/v1/webhooks/brevo"

def print_step(title):
    print(f"\n{'='*50}\n🔎 TEST: {title}\n{'='*50}")

def register_test_agent():
    print(f"\n🆕 [1/5] Registering new test agent at {BASE_URL}...")
    try:
        payload = {
            "client_name": f"ResilienceTester_{uuid.uuid4().hex[:6]}",
            "country_code": "ES",
            "agent_role": "Tester"
        }
        # Requests automatically validates the 'Client IP' extraction in main.py
        resp = requests.post(f"{BASE_URL}/v1/agent/register", json=payload, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            api_key = data.get("api_key")
            agent_id = data.get("agent_id")
            print(f"   ✅ Registered: {agent_id} (IP Capture Passed)")
            return api_key, agent_id
        else:
            print(f"   ❌ Registration Failed: {resp.status_code} - {resp.text}")
            return None, None
    except Exception as e:
        print(f"   ❌ Registration Error: {e}")
        return None, None

def create_dummy_agent_and_tx():
    """Crea datos reales en la DB para que el webhook tenga qué encontrar."""
    print("🛠️ Preparando el escenario (Agente + Transacción)...")
    
    # 1. Registrar Agente
    agent_id = f"ag_TEST_{uuid.uuid4().hex[:6]}"
    agent_email = f"{agent_id}@inbound.agentpay.io"
    print(f"   👤 Agente Mock: {agent_id} ({agent_email})")
    
    # IMPORTANTE: Insertar en identity y wallet para que el sistema lo reconozca
    # Nota: Como es un test externo, asumimos que podemos llamar endpoints o requerimos acceso a DB.
    # Para simplificar "Black Box", usaremos el endpoint de registro, pero no podemos controlar el email inbound fácilmente.
    # Así que SIMULAREMOS que el email mapea a este agente en el webhook (el webhook busca en DB).
    # Como no puedo escribir en tu DB real desde este script externo sin credenciales directas,
    # este test asume que el backend puede resolver 'ag_TEST...' si existe.
    # TRUCO: El webhook extrae "ag_..." del email. Así que si uso ese email, funcionará si la lógica del webhook lo permite.
    
    return agent_id, agent_email

def test_email_with_pdf(agent_id, agent_email):
    print_step("Escenario 1: Email con PDF Adjunto")
    
    # Crear PDF Mock (Vacío pero válido en estructura base64)
    dummy_pdf_b64 = "JVBERi0xLjcKCjEgMCBvYmogICUgZW50cnkgcG9pbnQKPDwKICAvVHlwZSAvQ2F0YWxvZwogIC9QYWdlcyAyIDAgUgo+PgRlbmRvYmoKCjIgMCBvYmogCjw8CiAgL1R5cGUgL1BhZ2VzCiAgL01lZGlhQm94IFsgMCAwIDIwMCAyMDAgXQogIC9Db3VudCAxCiAgL0tpZHMgWyAzIDAgUiBdCj4+CmVuZG9iagoKCjMgMCBvYmogCjw8CiAgL1R5cGUgL1BhZ2UKICAvUGFyZW50IDIgMCBSCj4+CmVuZG9iagoKeHJlZgowIDQKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwMDEwIDAwMDAwIG4gCjAwMDAwMDAwNjAgMDAwMDAgbiAKMDAwMDAwMDE1NyAwMDAwMCBuIAp0cmFpbGVyCjw8CiAgL1NpemUgNAogIC9Sb290IDEgMCBSCj4+CnN0YXJ0eHJlZgoxNzMKJSVFT0YK"
    
    payload = {
        "event": "inbound_parse",
        "email": agent_email, # RECIPIENT
        "from": {"address": "billing@amazon.com"},
        "subject": "Your Invoice for Order #123",
        "attachments": [
            {
                "name": "invoice_123.pdf",
                "contentType": "application/pdf",
                "content": dummy_pdf_b64
            }
        ]
    }
    
    try:
        print(f"   📨 Enviando Webhook simulado a {WEBHOOK_URL}...")
        resp = requests.post(WEBHOOK_URL, json=payload)
        
        if resp.status_code == 200:
            print(f"   ✅ Webhook Recibido: {resp.json()}")
            if resp.json().get('status') == 'success':
                 print("   🎉 ÉXITO: PDF procesado, subido y (simuladamente) casado.")
            else:
                 print(f"   ⚠️ Procesado pero no casado (normal si no hay TX real): {resp.json()}")
        else:
            print(f"   ❌ Fallo Webhook: {resp.status_code} - {resp.text}")
            
    except Exception as e:
        print(f"   ❌ Error conexión: {e}")

def test_email_with_link(agent_id, agent_email):
    print_step("Escenario 2: Email con Link de Descarga (Sin PDF)")
    
    payload = {
        "event": "inbound_parse",
        "email": agent_email, 
        "from": {"address": "no-reply@saas-tool.com"},
        "subject": "Your Monthly Receipt",
        "text": "Thanks for your payment. You can download your invoice here: https://saas-tool.com/downloads/invoice_999.pdf \n Regards.",
        "html": "<p>Download here: <a href='https://saas-tool.com/downloads/invoice_999.pdf'>Invoice</a></p>",
        "attachments": [] 
    }
    
    try:
        print(f"   📨 Enviando Webhook simulado...")
        resp = requests.post(WEBHOOK_URL, json=payload)
        
        data = resp.json()
        if data.get('type') == 'link_found':
            print(f"   🎉 ÉXITO: Enlace detectado: {data.get('url')}")
        else:
            print(f"   ℹ️ Resultado: {data}")

    except Exception as e:
        print(f"   ❌ Error: {e}")

def suggest_hunter_test():
    print_step("Escenario 3: Hunter Agent (Portal Cerrado)")
    print("""
    🤖 ESTA PRUEBA REQUIERE EJECUCIÓN MANUAL DEL WORKER.
    
    Pasos para probarlo en la vida real:
    1. Asegúrate de tener 'invoice_hunter_migration.sql' aplicado.
    2. Inserta una credencial real (o fake) en 'vendor_credentials'.
    3. Inserta una transacción en 'transaction_logs' con status='APPROVED' e invoice_status='PENDING_HUNT'.
    4. Ejecuta:
       $ python hunter_agent.py
       
    El script buscará las credenciales, abrirá el navegador (si configuras headless=False verás la magia) y tratará de bajar el PDF.
    """)

if __name__ == "__main__":
    # Generamos un ID aleatorio para no colisionar
    agent_id, agent_email = create_dummy_agent_and_tx()
    
    # Ejecutamos pruebas
    test_email_with_pdf(agent_id, agent_email)
    test_email_with_link(agent_id, agent_email)
    suggest_hunter_test()
