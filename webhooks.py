import requests
import json
import time

def send_webhook(url, event_type, data):
    """
    Envía notificaciones asíncronas al servidor del cliente.
    Ej: Cuando un humano aprueba un pago manual.
    """
    if not url:
        return # El cliente no configuró webhooks
        
    payload = {
        "event": event_type,
        "timestamp": int(time.time()),
        "data": data
    }
    
    print(f"🔔 WEBHOOK: Enviando '{event_type}' a {url}...")
    
    try:
        # En producción, esto debería ser una tarea en segundo plano (Celery/Redis)
        # para no bloquear, y tener retries automáticos.
        response = requests.post(
            url, 
            data=json.dumps(payload),
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        if response.status_code == 200:
            print("   ✅ Webhook entregado OK.")
        else:
            print(f"   ⚠️ Fallo al entregar Webhook: {response.status_code}")
            
    except Exception as e:
        print(f"   ❌ Error de conexión Webhook: {e}")
