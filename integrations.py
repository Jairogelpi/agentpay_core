import requests
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
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Agente:*\n{agent_id}"},
                        {"type": "mrkdwn", "text": f"*Monto:*\n${amount}"}
                    ]
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Proveedor:*\n{vendor}"},
                        {"type": "mrkdwn", "text": f"*Motivo:*\n{reason}"}
                    ]
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
        r = requests.post(webhook_url, json=payload)
        return r.status_code == 200
    except Exception as e:
        print(f"⚠️ Error enviando Slack: {e}")
        return False
