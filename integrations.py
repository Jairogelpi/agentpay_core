import requests
from loguru import logger
import json

def send_slack_approval(webhook_url, agent_id, amount, vendor, approval_link, reason="Transacción requiere aprobación"):
    try:
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "🚨 Solicitud de Gasto Detectada",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Agente:* {agent_id}\n*Monto:* ${amount}\n*Proveedor:* {vendor}\n*Motivo:* {reason}"
                    }
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "✅ Aprobar Transacción"},
                            "url": approval_link,
                            "style": "primary"
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "🛑 Bloquear Agente"},
                            "url": f"{approval_link}&action=block",
                            "style": "danger"
                        }
                    ]
                }
            ]
        }
        response = requests.post(webhook_url, json=payload)
        if response.status_code != 200:
            logger.warning(f"⚠️ Slack Webhook Falló: {response.text}")
            return False
        return True

    except Exception as e:
        logger.error(f"⚠️ Error enviando Slack: {e}")
        return False
