import requests
import time
from loguru import logger

BASE_URL = "https://agentpay-core.onrender.com"

def run_final_compliance_test():
    logger.info("🏛️ INICIANDO VALIDACIÓN DE INFRAESTRUCTURA CONTABLE")

    # 1. Registro
    payload_reg = {"client_name": f"Test_User_{int(time.time())}", "country": "ES"}
    reg_res = requests.post(f"{BASE_URL}/v1/agent/register", json=payload_reg).json()
    
    agent_id = reg_res.get('agent_id')
    api_key = reg_res.get('api_key')
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    
    logger.success(f"✅ Agente registrado: {agent_id}")

    # 2. Configuración y Fondeo
    requests.post(f"{BASE_URL}/v1/agent/settings", headers=headers, json={"agent_id": agent_id, "agent_role": "Senior Cloud Infrastructure Engineer"})
    topup_res = requests.post(f"{BASE_URL}/v1/topup/auto", headers=headers, json={"agent_id": agent_id, "amount": 100.0})
    if topup_res.status_code != 200:
        logger.error(f"❌ Topup falló: {topup_res.status_code} - {topup_res.text}")
        return
    logger.info("💰 Saldo fondeado exitosamente.")

    # 3. Pago de Prueba con Manejo de Errores
    logger.info("💸 Ejecutando pago...")
    pay_response = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json={
        "vendor": "cloud.google.com",
        "amount": 10.0,
        "description": "Test Multi-Currency",
        "justification": "Validación de infraestructura contable final"
    })

    if pay_response.status_code != 200:
        logger.error(f"❌ Error del Servidor ({pay_response.status_code}): {pay_response.text}")
        return

    pay_res = pay_response.json()
    if pay_res.get('status') in ['APPROVED', 'APPROVED_PENDING_AUDIT']:
        tx_id = pay_res.get('db_log_id') or pay_res.get('transaction_id')
        logger.success(f"✅ Pago aceptado. ID: {tx_id}")
        
        # 4. Verificación de campos en la DB
        time.sleep(5)
        status = requests.post(f"{BASE_URL}/v1/transactions/status", headers=headers, json={"transaction_id": tx_id}).json()
        logger.info(f"📊 Moneda: {status.get('settlement_currency')} | Tasa FX: {status.get('fx_rate')}")
    else:
        logger.error(f"❌ Pago rechazado por la IA: {pay_res.get('reason')}")

if __name__ == "__main__":
    run_final_compliance_test()