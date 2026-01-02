import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Email remitente verificado en Brevo (debe estar en el panel de Senders)
BREVO_VERIFIED_SENDER = os.environ.get("BREVO_SENDER_EMAIL", "gelpierreape@gmail.com")

def send_approval_email(to_email, agent_id, vendor, amount, tx_id):
    """
    Envía solicitud de aprobación de aprendizaje.
    """
    # ... (tu configuración SMTP de Brevo puerto 2525) ...
    smtp_host = "smtp-relay.brevo.com"
    smtp_port = 2525
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")

    msg = MIMEMultipart()
    msg['From'] = BREVO_VERIFIED_SENDER
    msg['To'] = to_email
    msg['Subject'] = f"⚠️ ¿Autorizas este pago?: {vendor}"
    
    # Enlace que apunta a tu servidor de Render
    # IMPORTANTE: codificar vendor si tiene espacios
    from urllib.parse import quote
    vendor_safe = quote(vendor)
    url_aprobacion = f"https://agentpay-core.onrender.com/v1/approve?tx_id={tx_id}&agent_id={agent_id}&vendor={vendor_safe}"

    body = f"""
    <html>
        <body>
            <h2>¿Autorizas este pago inusual?</h2>
            <p>El agente <b>{agent_id}</b> quiere pagar <b>${amount}</b> a <b>{vendor}</b>.</p>
            <p>Si apruebas, la IA aprenderá que este vendedor es confiable para el futuro.</p>
            <br>
            <a href="{url_aprobacion}" style="background-color: #2ecc71; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                APROBAR Y ENSEÑAR A LA IA
            </a>
        </body>
    </html>
    """
    msg.attach(MIMEText(body, 'html'))
    
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        print(f"✅ [EMAIL APPROVAL] Enviado a {to_email}")
        return True
    except Exception as e:
        print(f"❌ [SMTP ERROR] {e}")
        return False


def send_security_ban_alert(agent_id, reason, amount=0):
    """
    Envía alerta de seguridad cuando un agente es baneado.
    Configura SECURITY_ALERT_EMAIL para recibir estas alertas.
    """
    alert_email = os.environ.get("SECURITY_ALERT_EMAIL")
    
    if not alert_email:
        print(f"🚨 [SECURITY ALERT - NO EMAIL] Agent {agent_id} BANNED: {reason}")
        return False
    
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    
    if not all([smtp_host, smtp_user, smtp_pass]):
        print(f"🚨 [SECURITY ALERT - NO SMTP] Agent {agent_id} BANNED: {reason}")
        return False
    
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from datetime import datetime
    
    subject = f"🚨 SECURITY BAN: {agent_id}"
    body = f"""
    <h1 style="color: red;">⚠️ AGENT BANNED</h1>
    <table border="1" cellpadding="10">
        <tr><td><b>Agent ID</b></td><td>{agent_id}</td></tr>
        <tr><td><b>Reason</b></td><td>{reason}</td></tr>
        <tr><td><b>Amount Involved</b></td><td>${amount}</td></tr>
        <tr><td><b>Timestamp</b></td><td>{datetime.utcnow().isoformat()}</td></tr>
    </table>
    <p>This agent has been permanently banned from the platform.</p>
    <p>Review in Supabase: <code>SELECT * FROM wallets WHERE agent_id = '{agent_id}'</code></p>
    """
    
    msg = MIMEMultipart()
    msg['From'] = BREVO_VERIFIED_SENDER
    msg['To'] = alert_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))
    
    try:
        smtp_port = int(os.environ.get("SMTP_PORT", 587))
        print(f"🔌 [SMTP] Conectando a {smtp_host}:{smtp_port}...")
        
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
            server.starttls()
        
        with server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        
        print(f"🚨 [SECURITY ALERT SENT] Ban alert for {agent_id} -> {alert_email}")
        return True
    except Exception as e:
        print(f"❌ [ALERT EMAIL ERROR] {e}")
        return False

def send_ban_alert_to_owner(to_email, agent_id, vendor, amount, reason):
    """
    Envía alerta de BLOQUEO CRÍTICO al dueño del agente (cliente).
    Email con diseño alarmante para máxima visibilidad.
    """
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    
    if not all([smtp_host, smtp_user, smtp_pass, to_email]):
        print(f"⚠️ [BAN EMAIL] No se puede enviar - Configuración incompleta")
        return False
    
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from datetime import datetime
    
    subject = f"🚨 BLOQUEO CRÍTICO DE SEGURIDAD - {agent_id}"
    body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #dc3545; color: white; padding: 20px; text-align: center;">
            <h1 style="margin: 0;">⛔ CUENTA BLOQUEADA</h1>
        </div>
        
        <div style="padding: 20px; background: #fff3cd; border: 2px solid #dc3545;">
            <p style="font-size: 16px;">
                Su agente <strong>{agent_id}</strong> ha sido <strong>BLOQUEADO PERMANENTEMENTE</strong> 
                por actividad sospechosa detectada por nuestro sistema de seguridad con IA.
            </p>
            
            <h3 style="color: #dc3545;">Detalles del Incidente:</h3>
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Agente</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{agent_id}</td></tr>
                <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Proveedor</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{vendor}</td></tr>
                <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Monto</strong></td><td style="padding: 8px; border: 1px solid #ddd;">${amount}</td></tr>
                <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Motivo</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{reason}</td></tr>
                <tr><td style="padding: 8px; border: 1px solid #ddd;"><strong>Fecha/Hora</strong></td><td style="padding: 8px; border: 1px solid #ddd;">{datetime.utcnow().isoformat()} UTC</td></tr>
            </table>
            
            <p style="margin-top: 20px; color: #856404;">
                <strong>Nota:</strong> La transacción ha sido revertida y los fondos devueltos a su saldo.
                Si cree que esto es un error, contacte a soporte inmediatamente.
            </p>
        </div>
        
        <div style="padding: 15px; background: #f8f9fa; text-align: center; font-size: 12px; color: #6c757d;">
            AgentPay Security System | Este es un mensaje automático
        </div>
    </div>
    """
    
    msg = MIMEMultipart()
    msg['From'] = BREVO_VERIFIED_SENDER
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))
    
    try:
        smtp_port = int(os.environ.get("SMTP_PORT", 2525))  # Puerto 2525 para Brevo
        print(f"🔌 [SMTP] Conectando a {smtp_host}:{smtp_port} para enviar a {to_email}...")
        
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
            server.starttls()
        
        with server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        
        print(f"📧 [BAN ALERT SENT] Alerta crítica enviada a {to_email}")
        return True
    except Exception as e:
        print(f"❌ [BAN EMAIL ERROR] {e}")
        return False  # No raise - el baneo ya está hecho

