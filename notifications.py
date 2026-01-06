import os
import smtplib
from loguru import logger
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
    url_aprobacion = f"https://www.agentpay.it.com/v1/approve?tx_id={tx_id}&agent_id={agent_id}&vendor={vendor_safe}"

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
        logger.info(f"✅ [EMAIL APPROVAL] Enviado a {to_email}")
        return True
    except Exception as e:
        logger.error(f"❌ [SMTP ERROR] {e}")
        return False


def send_security_ban_alert(agent_id, reason, amount=0):
    """
    Envía alerta de seguridad cuando un agente es baneado.
    Configura SECURITY_ALERT_EMAIL para recibir estas alertas.
    """
    alert_email = os.environ.get("SECURITY_ALERT_EMAIL")
    
    if not alert_email:
        logger.warning(f"🚨 [SECURITY ALERT - NO EMAIL] Agent {agent_id} BANNED: {reason}")
        return False
    
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = os.getenv("SMTP_PORT")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    
    if not smtp_host or not smtp_port:
        logger.warning(f"🚨 [SECURITY ALERT - NO SMTP] Agent {agent_id} BANNED: {reason}")
        return False
    
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
        logger.info(f"🔌 [SMTP] Conectando a {smtp_host}:{smtp_port}...")
        
        with smtplib.SMTP(smtp_host, int(smtp_port), timeout=15) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, alert_email, msg.as_string())
            
        logger.success(f"🚨 [SECURITY ALERT SENT] Ban alert for {agent_id} -> {alert_email}")
        return True
    except Exception as e:
        logger.error(f"❌ [ALERT EMAIL ERROR] {e}")
        return False

def send_ban_alert_to_owner(to_email, agent_id, vendor, amount, reason):
    """
    Envía alerta de BLOQUEO CRÍTICO al dueño del agente (cliente).
    Email con diseño alarmante para máxima visibilidad.
    """
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = os.environ.get("SMTP_PORT")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    
    if not smtp_host or not smtp_port:
        logger.warning(f"⚠️ [BAN EMAIL] No se puede enviar - Configuración incompleta")
        return False
    
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
        logger.info(f"🔌 [SMTP] Conectando a {smtp_host}:{smtp_port} para enviar a {to_email}...")
        
        with smtplib.SMTP(smtp_host, int(smtp_port), timeout=15) as server:
            server.starttls() 
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to_email, msg.as_string())
            
        logger.success(f"📧 [BAN ALERT SENT] Alerta crítica enviada a {to_email}")
        return True
    except Exception as e:
        logger.error(f"❌ [BAN EMAIL ERROR] {e}")
        return False  # No raise - el baneo ya está hecho

def send_treasury_alert_email(to_email, balance, burn_rate, shortfall, reason):
    """
    Envía ALERTA DE TESORERÍA (Muerte Súbita Inminente).
    Prioridad MÁXIMA.
    """
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = os.environ.get("SMTP_PORT")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    
    if not smtp_host:
        logger.warning("⚠️ No SMTP config for Treasury Alert")
        return False

    from datetime import datetime
    
    subject = f"🚨 URGENT: TREASURY LIQUIDITY ALERT (${balance:,.2f})"
    body = f"""
    <div style="font-family: 'Courier New', monospace; max-width: 600px; margin: 0 auto; background: #000; color: #0f0; padding: 20px;">
        <h1 style="color: #f00; border-bottom: 2px solid #f00;">⚠️ LIQUIDITY CRUNCH DETECTED</h1>
        
        <p style="font-size: 18px;">
            PREDICTIVE AI HAS DETECTED A HIGH RISK OF INSOLVENCY.
        </p>
        
        <table style="width: 100%; border: 1px solid #0f0; margin-top: 20px; color: #0f0;">
            <tr><td style="padding: 10px; border-bottom: 1px solid #0f0;">REAL STRIPE BALANCE</td><td style="font-weight: bold; color: #fff;">${balance:,.2f}</td></tr>
            <tr><td style="padding: 10px; border-bottom: 1px solid #0f0;">CURRENT BURN RATE (7D)</td><td style="font-weight: bold; color: #fff;">${burn_rate:,.2f} / day</td></tr>
            <tr><td style="padding: 10px; border-bottom: 1px solid #0f0;">PROJECTED SHORTFALL</td><td style="font-weight: bold; color: #f00;">-${shortfall:,.2f}</td></tr>
            <tr><td style="padding: 10px; border-bottom: 1px solid #0f0;">TIMESTAMP</td><td>{datetime.utcnow().isoformat()} UTC</td></tr>
        </table>

        <div style="margin-top: 20px; border: 1px solid #f00; padding: 10px; color: #f00;">
            <strong>AI REASONING:</strong><br>
            {reason}
        </div>
        
        <p style="text-align: center; margin-top: 30px;">
            <a href="https://dashboard.stripe.com/topups" style="background: #f00; color: #fff; text-decoration: none; padding: 15px 30px; font-weight: bold;">>>> EXECUTE EMERGENCY TOP-UP <<<</a>
        </p>
    </div>
    """

    msg = MIMEMultipart()
    msg['From'] = BREVO_VERIFIED_SENDER
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))
    
    try:
        with smtplib.SMTP(smtp_host, int(smtp_port), timeout=15) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to_email, msg.as_string())
        logger.critical(f"📨 [TREASURY ALERT] Sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"❌ [TREASURY EMAIL ERROR] {e}")
        return False

def send_invoice_request_email(to_email, agent_id, vendor, amount, tx_id):
    """
    Envía solicitud de factura real al humano tras un gasto aprobado.
    """
    smtp_host = os.environ.get("SMTP_HOST", "smtp-relay.brevo.com")
    smtp_port = int(os.environ.get("SMTP_PORT", 2525))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")

    if not smtp_user: return False

    msg = MIMEMultipart()
    msg['From'] = BREVO_VERIFIED_SENDER
    msg['To'] = to_email
    msg['Subject'] = f"🧾 Factura Requerida: {vendor} (${amount})"

    # Enlace a tu frontend de conciliación
    upload_link = f"https://dashboard.agentpay.ai/reconcile/{tx_id}"

    body = f"""
    <html>
        <body style="font-family: Arial, sans-serif;">
            <div style="padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
                <h2 style="color: #2c3e50;">Conciliación de Gastos</h2>
                <p>Tu agente <b>{agent_id}</b> ha completado un pago correctamente.</p>
                
                <table style="width: 100%; margin: 20px 0; border-collapse: collapse;">
                    <tr style="background: #f8f9fa;">
                        <td style="padding: 10px;">Proveedor:</td>
                        <td style="padding: 10px;"><b>{vendor}</b></td>
                    </tr>
                    <tr>
                        <td style="padding: 10px;">Monto:</td>
                        <td style="padding: 10px;"><b>${amount}</b></td>
                    </tr>
                </table>

                <p>Para cumplir con la normativa fiscal, por favor sube la factura original del proveedor.</p>
                
                <div style="text-align: center; margin-top: 30px;">
                    <a href="{upload_link}" style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                        📤 SUBIR FACTURA ORIGINAL
                    </a>
                </div>
            </div>
        </body>
    </html>
    """
    msg.attach(MIMEText(body, 'html'))
    
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        logger.info(f"📧 [INVOICE REQ] Solicitud enviada a {to_email}")
        return True
    except Exception as e:
        logger.error(f"❌ [SMTP ERROR] {e}")
        return False
