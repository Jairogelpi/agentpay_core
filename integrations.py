import requests
from loguru import logger
import json

def send_slack_approval(webhook_url, agent_id, amount, vendor, approval_link, reason="No especificado"):
    """
    Envía una notificación de aprobación a Slack con un formato de bloques validado.
    """
    # Saneamiento de la razón para evitar roturas de JSON
    clean_reason = str(reason).replace('"', "'")[:200]
    
    # Construcción del payload siguiendo el estándar Block Kit
    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🛡️ Alerta de Seguridad AgentPay",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Agente:*\n{agent_id}"},
                    {"type": "mrkdwn", "text": f"*Monto:*\n${amount:.2f}"}
                ]
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Proveedor:*\n{vendor}"},
                    {"type": "mrkdwn", "text": f"*Estado:*\nRevisión de Seguridad"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Motivo del Bloqueo/Flag:* {clean_reason}"
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Revisar y Aprobar"},
                        "style": "primary",
                        "url": approval_link,
                        "action_id": "approve_button"
                    }
                ]
            }
        ]
    }

    try:
        # Envío de la petición con timeout para evitar bloqueos del sistema
        response = requests.post(webhook_url, json=payload, timeout=10)
        if response.status_code == 200:
            logger.success(f"✅ Notificación Slack enviada correctamente para {agent_id}")
            return True
        else:
            # Captura de error detallado de la API de Slack
            logger.error(f"❌ Error de Slack (Status {response.status_code}): {response.text}")
            return False
    except Exception as e:
        logger.error(f"⚠️ Fallo crítico al conectar con el Webhook de Slack: {e}")
        return False
