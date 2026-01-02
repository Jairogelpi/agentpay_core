import requests
from loguru import logger
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
    
    logger.info(f"🔔 WEBHOOK: Enviando '{event_type}' a {url}...")
    
    try:
        # En producción, esto debería ser una tarea en segundo plano (Celery/Redis)
        # para no bloquear, y tener retries automáticos.
        response = requests.post(
            url, 
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=5
        )
        if response.status_code in [200, 201, 204]:
            logger.debug("   ✅ Webhook entregado OK.")
        else:
            logger.warning(f"   ⚠️ Fallo al entregar Webhook: {response.status_code}")
            
    except Exception as e:
        logger.error(f"   ❌ Error de conexión Webhook: {e}")
