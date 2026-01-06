import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

# --- CONFIGURACIÓN CENTRALIZADA (Single Source of Truth) ---
# Se leen una sola vez al importar el módulo.
SMTP_HOST = os.getenv("SMTP_HOST", "smtp-relay.brevo.com") # Default a Brevo
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))             # Default estándar
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASSWORD")
SMTP_SENDER = os.getenv("SMTP_SENDER", "alerts@agentpay.ai")

def _send_smtp_email(to_email, subject, html_content):
    """
    Función interna privada que maneja la conexión SMTP.
    Usa SIEMPRE las variables de entorno centralizadas.
    """
    if not to_email:
        logger.warning("⚠️ Intento de enviar email sin destinatario.")
        return False

    if not SMTP_USER or not SMTP_PASS:
        logger.error("❌ Credenciales SMTP no configuradas (SMTP_USER / SMTP_PASSWORD).")
        return False

    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_SENDER
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(html_content, 'html'))

        # Conexión segura
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
        server.quit()
        
        logger.info(f"📧 Email enviado a {to_email}: {subject}")
        return True

    except Exception as e:
        logger.error(f"❌ Error enviando email a {to_email}: {e}")
        return False

# --- FUNCIONES DE NEGOCIO ---

def send_approval_email(to_email, agent_id, vendor, amount, magic_link):
    """
    Solicita aprobación humana para una transacción sospechosa o alta.
    """
    subject = f"👮 Aprobación Requerida: {agent_id} quiere gastar ${amount}"
    
    html = f"""
    <h2>Solicitud de Aprobación</h2>
    <p>El agente <b>{agent_id}</b> intenta realizar un pago:</p>
    <ul>
        <li><b>Proveedor:</b> {vendor}</li>
        <li><b>Monto:</b> ${amount}</li>
    </ul>
    <p>El sistema ha detenido esta operación por precaución.</p>
    <br>
    <a href="{magic_link}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
        ✅ APROBAR TRANSACCIÓN
    </a>
    <p style="font-size: small; color: gray;">Si no reconoces esta actividad, ignora este correo.</p>
    """
    return _send_smtp_email(to_email, subject, html)

def send_security_ban_alert(agent_id, reason, amount):
    """
    Alerta crítica al equipo de seguridad interno (ADMIN_EMAIL).
    """
    admin_email = os.getenv("ADMIN_EMAIL")
    if not admin_email:
        logger.warning("⚠️ ADMIN_EMAIL no configurado. No se pudo enviar alerta de seguridad.")
        return False

    subject = f"🚨 SEGURIDAD: Agente {agent_id} BANEADO"
    
    html = f"""
    <h2 style="color: red;">ALERTA DE SEGURIDAD CRÍTICA</h2>
    <p>El sistema de IA ha detectado actividad maliciosa y ha ejecutado un <b>BANEO AUTOMÁTICO</b>.</p>
    <ul>
        <li><b>Agente:</b> {agent_id}</li>
        <li><b>Motivo:</b> {reason}</li>
        <li><b>Intento de Gasto:</b> ${amount}</li>
    </ul>
    <p>Por favor, revisa los logs forenses inmediatamente.</p>
    """
    return _send_smtp_email(admin_email, subject, html)

def send_ban_alert_to_owner(to_email, agent_id, vendor, amount, reason):
    """
    Notifica al CLIENTE que su agente ha sido bloqueado.
    """
    subject = f"⛔ Tu Agente {agent_id} ha sido bloqueado"
    
    html = f"""
    <h2>Notificación de Bloqueo de Seguridad</h2>
    <p>Tu agente <b>{agent_id}</b> ha sido detenido y bloqueado por violar los protocolos de seguridad.</p>
    <ul>
        <li><b>Intento:</b> Compra en {vendor} (${amount})</li>
        <li><b>Razón Detectada:</b> {reason}</li>
    </ul>
    <p>Si crees que esto es un error, contacta a soporte.</p>
    """
    return _send_smtp_email(to_email, subject, html)

def send_invoice_request_email(to_email, agent_id, vendor, amount, tx_id):
    """
    Solicita al usuario que suba la factura de un gasto ya aprobado.
    """
    subject = f"🧾 Factura Pendiente: {vendor} (${amount})"
    
    html = f"""
    <h2>Sube tu Factura</h2>
    <p>El gasto en <b>{vendor}</b> por <b>${amount}</b> se ha procesado correctamente.</p>
    <p>Para cumplir con la normativa fiscal, por favor sube el comprobante:</p>
    <br>
    <a href="https://agentpay.ai/upload/{tx_id}" style="background-color: #008CBA; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
        📤 SUBIR FACTURA AHORA
    </a>
    """
    return _send_smtp_email(to_email, subject, html)

def send_treasury_alert_email(to_email, balance, burn_rate, shortfall, reason):
    """
    Alerta de liquidez baja para el tesorero.
    """
    subject = f"⚠️ ALERTA DE TESORERÍA: Saldo Bajo (${balance:,.2f})"
    
    html = f"""
    <h2 style="color: orange;">Riesgo de Liquidez Detectado</h2>
    <p>El sistema predictivo ha detectado que los fondos se agotarán pronto.</p>
    <ul>
        <li><b>Saldo Actual:</b> ${balance:,.2f}</li>
        <li><b>Burn Rate:</b> ${burn_rate:,.2f} / día</li>
        <li><b>Déficit Estimado:</b> ${shortfall:,.2f}</li>
    </ul>
    <p><b>Razón:</b> {reason}</p>
    <p>Se recomienda realizar una recarga inmediata.</p>
    """
    return _send_smtp_email(to_email, subject, html)
