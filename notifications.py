import os

def send_approval_email(to_email, agent_id, vendor, amount, link):
    """
    Simula el envío de un correo electrónico transaccional.
    En producción, aquí conectaríamos con SendGrid, AWS SES o Resend.
    """
    if not to_email:
        print("⚠️ [EMAIL] No se envió email porque falta el destinatario.")
        return

    subject = f"⚠️ [ACTION REQUIRED] {agent_id} blocked for ${amount}"
    
    # HTML simple para el email
    body = f"""
    <h1>Solicitud de Aprobación de Pago</h1>
    <p>Su Agente <b>{agent_id}</b> intenta realizar un pago detenido por seguridad.</p>
    <ul>
        <li><b>Proveedor:</b> {vendor}</li>
        <li><b>Monto:</b> ${amount}</li>
    </ul>
    <p>Si usted reconoce esta operación, haga clic abajo:</p>
    <a href="{link}" style="background:green; color:white; padding:10px;">APROBAR PAGO</a>
    <p>Si no lo reconoce, ignore este mensaje.</p>
    """

    # Real SMTP Implementation
    # Requiere variables de entorno: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = os.environ.get("SMTP_PORT", 587)
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    
    if not all([smtp_host, smtp_user, smtp_pass]):
        print("❌ [EMAIL ERROR] No SMTP credentials configured. Email NOT sent.")
        # En modo estricto, esto debería ser una excepción, pero para evitar crash total en demo inicial:
        raise Exception("Strict Mode Error: SMTP Configuration Missing. Cannot send real email.")

    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    msg = MIMEMultipart()
    msg['From'] = f"AgentPay Security <{smtp_user}>"
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))

    try:
        server = smtplib.SMTP(smtp_host, int(smtp_port))
        server.starttls()
        server.login(smtp_user, smtp_pass)
        text = msg.as_string()
        server.sendmail(smtp_user, to_email, text)
        server.quit()
        print(f"✅ [EMAIL SENT] Enviado real vía {smtp_host} a {to_email}")
        return True
    except Exception as e:
        print(f"❌ [SMTP ERROR] Fallo al enviar: {str(e)}")
        raise e
