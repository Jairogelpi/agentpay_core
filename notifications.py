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

    # Simulación de envío
    print(f"\n📧 [EMAIL SYSTEM] ENVIANDO CORREO A: {to_email}")
    print(f"   | Asunto: {subject}")
    print(f"   | Link: {link}")
    print(f"   | (Enviado vía MockSMTP Service)\n")
    
    # Aquí iría el código real:
    # sendgrid.send(to=to_email, subject=subject, html=body)
    return True
