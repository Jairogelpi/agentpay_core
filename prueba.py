import requests
import time
from loguru import logger

BASE_URL = "https://agentpay-core.onrender.com"

def run_compliance_test():
    logger.info("🏛️ INICIANDO REGISTRO Y AUDITORÍA DE CONTABILIDAD LEGAL")

    # 1. REGISTRO (Obtenemos credenciales vivas)
    payload_registro = {
        "client_name": f"Enterprise_User_{int(time.time())}",
        "country": "ES" 
    }
    reg_response = requests.post(f"{BASE_URL}/v1/agent/register", json=payload_registro)
    
    if reg_response.status_code != 200:
        logger.error(f"Fallo en Registro: {reg_response.text}")
        return

    data = reg_response.json()
    agent_id = data.get('agent_id')
    api_key = data.get('api_key') 

    logger.success(f"✅ Agente Registrado: {agent_id}")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    # 2. CONFIGURACIÓN DE POLÍTICAS
    requests.post(f"{BASE_URL}/v1/agent/settings", headers=headers, json={
        "agent_id": agent_id,
        "agent_role": "Senior Cloud Infrastructure Engineer"
    })

    # 3. RECARGA DE SALDO
    requests.post(f"{BASE_URL}/v1/topup/auto", json={"agent_id": agent_id, "amount": 100.0})
    logger.info("💰 Saldo fondeado exitosamente.")

    # 4. PAGO B2B (Validación de Oracle y Contabilidad)
    logger.info("💸 Ejecutando pago de prueba legal...")
    payment_payload = {
        "vendor": "cloud.google.com",
        "amount": 25.50,
        "description": "Compute Engine Micro Instance",
        "justification": "Servidor de monitoreo para cumplimiento legal"
    }
    
    pay_res = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json=payment_payload)
    
    if pay_res.status_code == 200:
        pay_data = pay_res.json()
        tx_id = pay_data.get('db_log_id')
        logger.success(f"✅ Pago Procesado. ID: {tx_id}")
        
        # ESPERA CRÍTICA: La IA y el PDF se generan asíncronamente
        logger.info("⏳ Esperando sellado forense y generación de PDF...")
        time.sleep(15)

        # 5. EXPORTACIÓN CSV (Con Token de Autorización)
        logger.info("📥 Generando reporte contable CSV...")
        export_res = requests.get(
            f"{BASE_URL}/v1/accounting/export-csv?month=1&year=2026",
            headers=headers
        )
        
        if export_res.status_code == 200:
            logger.success("✅ Reporte contable exportado.")
        else:
            logger.error(f"❌ Error en exportación: {export_res.status_code}")
    else:
        logger.error(f"Error en Pago: {pay_res.text}")

if __name__ == "__main__":
    run_compliance_test()