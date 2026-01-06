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

# --- INBOUND PARSE LISTENER (BREVO) ---
import base64
from fastapi import Request
from engine import UniversalEngine 
from ai_guard import match_receipt_to_transaction 

# Lazy initialization avoids circular imports if engine imports webhooks
_engine_instance = None
def get_engine():
    global _engine_instance
    if not _engine_instance:
        _engine_instance = UniversalEngine()
    return _engine_instance

def extract_text_from_pdf(file_bytes):
    """
    Intenta extraer texto de un PDF (Necesita pypdf).
    Fallback: Retorna string vacío si falla.
    """
    try:
        import io
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(file_bytes))
        text = ""
        for page in reader.pages:
            text += page.extract_text() + "\n"
        return text
    except ImportError:
        logger.warning("⚠️ pypdf no instalado. No se puede leer el PDF para IA Matching.")
        return ""
    except Exception as e:
        logger.error(f"Error parseando PDF: {e}")
        return ""

async def handle_brevo_email(request: Request):
    """
    Recibe el JSON de Brevo Inbound Parse.
    Busca adjuntos (PDFs) o enlaces de descarga.
    """
    try:
        data = await request.json()
    except Exception:
        # A veces viene como Form Data
        return {"status": "ignored", "reason": "Not JSON"}
    
    # 1. Extraer datos básicos
    # Brevo structure varies, check docs. Assuming JSON payload.
    sender = data.get('from', {}).get('address', '') or data.get('From', '')
    recipient = data.get('email', '') or data.get('To', '') # El email de tu agente
    subject = data.get('subject', '') or data.get('Subject', '')
    attachments = data.get('attachments', []) # Lista de adjuntos
    
    engine = get_engine()
    
    # Resolver ID del agente desde el email (ej: ag_123@tuapp.com -> ag_123)
    # Buscamos en identities
    try:
        res = engine.db.table("identities").select("agent_id").eq("email", recipient).single().execute()
        agent_id = res.data.get('agent_id') if res.data else None
    except:
        agent_id = None
        
    # Si no encontramos por email exacto, intentamos parsear el TO "ag_...@"
    if not agent_id and "@" in recipient:
        potential_id = recipient.split("@")[0]
        if potential_id.startswith("ag_"):
            agent_id = potential_id

    if not agent_id:
        return {"status": "ignored", "reason": f"No agent found for email {recipient}"}

    logger.info(f"📧 Email recibido para {agent_id} de {sender}. Adjuntos: {len(attachments)}")

    # 2. ESCENARIO: FACTURA ADJUNTA (PDF)
    for att in attachments:
        filename = att.get('name', 'invoice.pdf')
        content_b64 = att.get('content')
        content_type = att.get('contentType', '')

        if 'pdf' in content_type.lower() or 'pdf' in filename.lower():
            try:
                # A. Decodificar y Subir a Storage
                file_data = base64.b64decode(content_b64)
                path = f"invoices/{agent_id}/{filename}"
                engine.db.storage.from_("receipts").upload(path, file_data)
                public_url = engine.db.storage.from_("receipts").get_public_url(path)

                # B. Usar IA para leer el PDF y casar con la transacción
                text_content = extract_text_from_pdf(file_data) 
                
                # Si tenemos texto, intentamos match
                if text_content:
                    match = await match_receipt_to_transaction(text_content, agent_id, engine.db)

                    if match.get('match_found'):
                        tx_id = match.get('transaction_id')
                        engine.db.table("transaction_logs").update({
                            "invoice_status": "FOUND_EMAIL",
                            "invoice_url": public_url
                        }).eq("id", tx_id).execute()
                        logger.success(f"✅ Factura encontrada por Email y vinculada a TX {tx_id}")
                        return {"status": "success", "matched_tx": tx_id}
            except Exception as e:
                logger.error(f"Error procesando adjunto: {e}")

    # 3. ESCENARIO: SIN ADJUNTO (Posible Link de Descarga)
    if not attachments:
        logger.info("   🔍 Sin adjuntos. Buscando enlaces en el cuerpo...")
        body_text = data.get('text', '') or data.get('html', '')
        
        # Heurística simple (En prod: Usar ai_guard.match_receipt_link(body_text))
        # Buscamos patrones comunes de enlaces de facturas
        import re
        # Regex básico para encontrar URLs
        urls = re.findall(r'(https?://[^\s<>"]+|www\.[^\s<>"]+)', body_text)
        
        potential_invoice_links = []
        keywords = ['invoice', 'factura', 'receipt', 'download', 'descargar', 'billing']
        
        for url in urls:
            # Check si la URL o el texto cercano (difícil en raw regex) parece relevante
            # Aquí simplificamos revisando si la url tiene palabras clave o es un PDF
            if any(k in url.lower() for k in keywords) or url.lower().endswith('.pdf'):
                potential_invoice_links.append(url)
        
        if potential_invoice_links:
            # Enviamos el primer link candidato al Hunter Agent para que intente descargarlo
            # O lo guardamos en la transacción para revisión
            logger.info(f"   🔗 Enlace detectado: {potential_invoice_links[0]}")
            
            # Buscamos la transacción reciente
            candidates = engine.db.table("transaction_logs")\
                .select("id")\
                .eq("agent_id", agent_id)\
                .eq("invoice_status", "PENDING_HUNT")\
                .order("created_at", desc=True)\
                .limit(1)\
                .execute()
                
            if candidates.data:
                tx_id = candidates.data[0]['id']
                # Marcamos que hemos encontrado un link, podríamos activar un "Link Crawler Agent"
                engine.db.table("transaction_logs").update({
                    "invoice_status": "FOUND_LINK",
                    "invoice_url": potential_invoice_links[0] # Guardamos el link raw por ahora
                }).eq("id", tx_id).execute()
                return {"status": "success", "type": "link_found", "url": potential_invoice_links[0]}
    
    return {"status": "processed"}
