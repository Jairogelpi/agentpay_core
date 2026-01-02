import requests
import json
from loguru import logger

# Configuración del entorno de prueba
BASE_URL = "https://agentpay-core.onrender.com"
TARGET_AGENT = "ag_1583476b1a31"  # Tu agente de la prueba anterior

def simulate_webhook_attack():
    logger.info(f"🚨 INICIANDO SIMULACIÓN DE ATAQUE: Inyección de Saldo en {TARGET_AGENT}")

    # 1. Construir el Payload Falso (Simulando un pago de $1,000,000)
    fake_payload = {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "evt_fake_attack_2026",
                "amount_total": 100000000, # $1,000,000.00 en centavos
                "currency": "usd",
                "payment_status": "paid",
                "metadata": {
                    "agent_id": TARGET_AGENT,
                    "type": "topup"
                }
            }
        }
    }

    # 2. Intentar el envío SIN firma válida o con firma falsa
    headers = {
        "Content-Type": "application/json",
        "Stripe-Signature": "t=1735858800,v1=falsified_hash_to_steal_money" # Firma malintencionada
    }

    logger.warning("Attempting to bypass security with a fake signature...")
    
    try:
        response = requests.post(
            f"{BASE_URL}/webhook", 
            data=json.dumps(fake_payload), 
            headers=headers
        )

        # 3. Analizar el Resultado
        if response.status_code == 400:
            logger.success("✅ DEFENSA EXITOSA: El servidor rechazó el webhook falso con 400 Bad Request.")
            logger.info(f"Respuesta del servidor: {response.json().get('detail')}")
        elif response.status_code == 200:
            logger.critical("🔥 VULNERABILIDAD DETECTADA: El servidor aceptó un pago falso. ¡El saldo fue robado!")
        else:
            logger.error(f"Resultado inesperado: Código {response.status_code}")

    except Exception as e:
        logger.error(f"Error durante el ataque: {e}")

if __name__ == "__main__":
    simulate_webhook_attack()